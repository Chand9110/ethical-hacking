import * as cheerio from 'cheerio';
import { db, logAuditEvent } from '../db.ts';
import { DEMO_STORE_BASE_URL, safeExternalFetch, validateScanTargetUrl } from '../security/urlValidator.ts';
import { fetchDemoStorePage } from './demoStore.ts';
import { getRecommendationForRule } from './recommendations.ts';
import { analyzeAndAssessRisk, type RawFinding } from './riskEngine.ts';

export interface ScanConfigInput {
  websiteId: number;
  userId: number;
  userEmail: string;
  targetUrl: string;
  isDemoTarget: boolean;
  scanMode: 'quick' | 'standard' | 'comprehensive';
  maxPages: number;
  checkSqli: boolean;
  checkXss: boolean;
  checkHeaders: boolean;
  checkCookies: boolean;
  checkMisconfig: boolean;
}

const activeScanControllers = new Map<number, AbortController>();

export function stopActiveScan(scanId: number): boolean {
  const controller = activeScanControllers.get(scanId);
  if (controller) {
    controller.abort();
    activeScanControllers.delete(scanId);
    db.prepare(
      `UPDATE Scan_History
       SET status = 'stopped', completed_at = datetime('now'), current_url = ''
       WHERE id = ? AND status IN ('queued', 'running')`
    ).run(scanId);
    return true;
  }
  return false;
}

export function isScanRunning(scanId: number): boolean {
  return activeScanControllers.has(scanId);
}

async function fetchTargetPage(
  url: string,
  isDemoTarget: boolean,
  signal: AbortSignal
): Promise<{
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  responseTimeMs: number;
}> {
  if (signal.aborted) {
    throw new Error('Scan aborted by user');
  }
  if (isDemoTarget) {
    // Brief pacing so real-time progress indicator is observable during demonstrations
    await new Promise((resolve) => setTimeout(resolve, 280));
    if (signal.aborted) {
      throw new Error('Scan aborted by user');
    }
    return fetchDemoStorePage(url);
  }
  return safeExternalFetch(url, signal);
}

function parseSetCookieAttributes(rawCookie: string): {
  name: string;
  hasHttpOnly: boolean;
  hasSecure: boolean;
  hasSameSite: boolean;
} {
  const parts = rawCookie.split(';').map((p) => p.trim());
  const nameVal = parts[0] || '';
  const name = nameVal.split('=')[0]?.trim() || 'cookie';
  const attrs = parts.slice(1).map((a) => a.toLowerCase());

  return {
    name,
    hasHttpOnly: attrs.some((a) => a === 'httponly'),
    hasSecure: attrs.some((a) => a === 'secure'),
    hasSameSite: attrs.some((a) => a.startsWith('samesite=')),
  };
}

function buildFinding(
  pageId: number | null,
  ruleCode: string,
  name: string,
  affectedUrl: string,
  parameterName: string,
  severity: 'Critical' | 'High' | 'Medium' | 'Low',
  confidence: 'High' | 'Medium' | 'Low',
  description: string,
  evidence: string,
  potentialImpact: string,
  sitewideDedupe = false
): RawFinding {
  const rule = getRecommendationForRule(ruleCode);
  return {
    page_id: pageId,
    rule_code: ruleCode,
    name,
    category: rule.category,
    affected_url: affectedUrl,
    parameter_name: parameterName,
    severity,
    confidence,
    description,
    evidence,
    potential_impact: potentialImpact,
    owasp_top10: rule.owasp_top10,
    owasp_wstg: rule.owasp_wstg,
    owasp_asvs: rule.owasp_asvs,
    nist_800_115: rule.nist_800_115,
    sitewide_dedupe: sitewideDedupe,
  };
}

const DB_ERROR_SIGNATURES: { pattern: RegExp; engine: string }[] = [
  { pattern: /SQLITE_ERROR|sqlite3\.OperationalError|near ".*": syntax error/i, engine: 'SQLite' },
  { pattern: /You have an error in your SQL syntax|mysql_fetch|mysqli_/i, engine: 'MySQL' },
  { pattern: /PG::SyntaxError|PSQLException|unterminated quoted string at or near/i, engine: 'PostgreSQL' },
  { pattern: /ORA-\d{4,5}:|ODBC SQL Server Driver|Microsoft OLE DB Provider/i, engine: 'Oracle/MSSQL' },
  { pattern: /PDOException|SQLSTATE\[[A-Z0-9]+\]/i, engine: 'PDO SQL' },
];

export function startScanJob(config: ScanConfigInput): number {
  const insertScan = db.prepare(
    `INSERT INTO Scan_History (
      website_id, user_id, status, scan_mode, max_pages,
      check_sqli, check_xss, check_headers, check_cookies, check_misconfig,
      pages_scanned, vulnerabilities_found, current_url
    ) VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)`
  );

  const info = insertScan.run(
    config.websiteId,
    config.userId,
    config.scanMode,
    config.maxPages,
    config.checkSqli ? 1 : 0,
    config.checkXss ? 1 : 0,
    config.checkHeaders ? 1 : 0,
    config.checkCookies ? 1 : 0,
    config.checkMisconfig ? 1 : 0,
    config.targetUrl
  );

  const scanId = Number(info.lastInsertRowid);
  const controller = new AbortController();
  activeScanControllers.set(scanId, controller);

  logAuditEvent({
    userId: config.userId,
    userEmail: config.userEmail,
    action: 'SCAN_STARTED',
    target: config.targetUrl,
    details: `Scan #${scanId} started (mode=${config.scanMode}, maxPages=${config.maxPages})`,
  });

  // Run async scan loop in background without blocking HTTP request
  void executeScanWorkflow(scanId, config, controller.signal);

  return scanId;
}

async function executeScanWorkflow(
  scanId: number,
  config: ScanConfigInput,
  signal: AbortSignal
): Promise<void> {
  const rawFindings: RawFinding[] = [];

  try {
    const validatedRoot = await validateScanTargetUrl(config.targetUrl);
    const rootUrlObj = new URL(validatedRoot.normalizedUrl);
    const origin = rootUrlObj.origin;

    const visited = new Set<string>();
    const queue: string[] = [validatedRoot.normalizedUrl];
    let pagesScanned = 0;

    const insertPageStmt = db.prepare(
      `INSERT INTO Scanned_Pages (
        scan_id, url, http_status, content_type, response_time_ms,
        forms_count, inputs_count, links_count, headers_json, cookies_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const updateProgressStmt = db.prepare(
      `UPDATE Scan_History SET pages_scanned = ?, vulnerabilities_found = ?, current_url = ? WHERE id = ?`
    );

    while (queue.length > 0 && pagesScanned < config.maxPages) {
      if (signal.aborted) break;

      const currentUrl = queue.shift()!;
      const canonical = currentUrl.split('#')[0];
      if (visited.has(canonical)) continue;
      visited.add(canonical);

      updateProgressStmt.run(pagesScanned, rawFindings.length, canonical, scanId);

      let pageResp;
      try {
        pageResp = await fetchTargetPage(canonical, validatedRoot.isDemoTarget, signal);
      } catch (err) {
        if (signal.aborted) break;
        // Skip individual unreachable subpages after recording root failure if first page
        if (pagesScanned === 0) {
          throw err;
        }
        continue;
      }

      const contentType = pageResp.headers['content-type'] || 'text/html';
      const isHtml = contentType.toLowerCase().includes('text/html') || contentType.toLowerCase().includes('xhtml');
      const $ = isHtml ? cheerio.load(pageResp.body) : null;

      const forms = $ ? $('form') : null;
      const inputs = $ ? $('input, select, textarea') : null;
      const links = $ ? $('a[href]') : null;

      const formsCount = forms ? forms.length : 0;
      const inputsCount = inputs ? inputs.length : 0;
      const linksCount = links ? links.length : 0;

      const pageInsert = insertPageStmt.run(
        scanId,
        pageResp.finalUrl,
        pageResp.status,
        contentType,
        pageResp.responseTimeMs,
        formsCount,
        inputsCount,
        linksCount,
        JSON.stringify(pageResp.headers),
        JSON.stringify(pageResp.setCookies)
      );
      const pageId = Number(pageInsert.lastInsertRowid);
      pagesScanned += 1;

      // Collect same-origin links for crawling
      if ($ && links) {
        links.each((_idx, el) => {
          const href = $(el).attr('href');
          if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) {
            return;
          }
          try {
            const resolved = new URL(href, pageResp.finalUrl);
            if (resolved.origin === origin && (resolved.protocol === 'http:' || resolved.protocol === 'https:')) {
              const nextUrl = resolved.toString().split('#')[0];
              if (!visited.has(nextUrl) && !queue.includes(nextUrl)) {
                queue.push(nextUrl);
              }
            }
          } catch {
            // Ignore malformed hrefs
          }
        });
      }

      // 1. Security Headers Audit
      if (config.checkHeaders) {
        const h = pageResp.headers;
        if (!h['content-security-policy']) {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-CSP-01',
              'Missing Content-Security-Policy (CSP) Header',
              pageResp.finalUrl,
              'Content-Security-Policy',
              'Medium',
              'High',
              'The server response does not include a Content-Security-Policy header to restrict script origins and frame embedding.',
              `HTTP ${pageResp.status} response headers omitted "content-security-policy".`,
              'Increases exposure to cross-site scripting and unauthorized third-party payment script injection.',
              true
            )
          );
        } else if (/unsafe-inline|unsafe-eval/i.test(h['content-security-policy'])) {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-CSP-01',
              'Permissive Content-Security-Policy (unsafe-inline / unsafe-eval)',
              pageResp.finalUrl,
              'Content-Security-Policy',
              'Medium',
              'High',
              'The Content-Security-Policy permits unsafe-inline or unsafe-eval script execution, weakening XSS mitigation.',
              `Content-Security-Policy: ${h['content-security-policy'].slice(0, 180)}`,
              'Attackers who achieve HTML injection may still execute inline scripts.',
              true
            )
          );
        }

        if (pageResp.finalUrl.startsWith('https://') && !h['strict-transport-security']) {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-HSTS-01',
              'Missing HTTP Strict-Transport-Security (HSTS) Header',
              pageResp.finalUrl,
              'Strict-Transport-Security',
              'Medium',
              'High',
              'HTTPS responses do not advertise Strict-Transport-Security to enforce TLS connections.',
              'Response headers omitted "strict-transport-security".',
              'Initial unencrypted requests can be targeted by SSL-stripping downgrade attacks.',
              true
            )
          );
        }

        if (!h['x-frame-options'] && !(h['content-security-policy'] && /frame-ancestors/i.test(h['content-security-policy']))) {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-XFO-01',
              'Missing Clickjacking Protection (X-Frame-Options)',
              pageResp.finalUrl,
              'X-Frame-Options',
              'Medium',
              'High',
              'Neither X-Frame-Options nor CSP frame-ancestors is configured, permitting iframe embedding.',
              'Response headers omitted "x-frame-options" and CSP "frame-ancestors".',
              'Checkout or account actions could be overlaid in transparent attacker frames.',
              true
            )
          );
        }

        if (!h['x-content-type-options'] || h['x-content-type-options'].toLowerCase() !== 'nosniff') {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-XCTO-01',
              'Missing X-Content-Type-Options: nosniff Header',
              pageResp.finalUrl,
              'X-Content-Type-Options',
              'Low',
              'High',
              'Responses lack X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff content types.',
              `Observed X-Content-Type-Options: ${h['x-content-type-options'] ?? 'not set'}`,
              'Uploaded or cached files could be misinterpreted as executable scripts in older browsers.',
              true
            )
          );
        }

        if (!h['referrer-policy']) {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-REF-01',
              'Missing Referrer-Policy Header',
              pageResp.finalUrl,
              'Referrer-Policy',
              'Low',
              'High',
              'Pages do not emit a Referrer-Policy header to limit URL leakage to external sites.',
              'Response headers omitted "referrer-policy".',
              'Query strings on storefront or order links may leak via HTTP Referer headers.',
              true
            )
          );
        }

        if (h['x-powered-by'] || (h['server'] && /\d+\.\d+/.test(h['server']))) {
          rawFindings.push(
            buildFinding(
              pageId,
              'HDR-INFO-01',
              'Server & Technology Version Banner Disclosed',
              pageResp.finalUrl,
              h['x-powered-by'] ? 'X-Powered-By' : 'Server',
              'Low',
              'High',
              'HTTP response headers expose software stack and exact version metadata.',
              `Headers observed: ${h['server'] ? `Server: ${h['server']}` : ''} ${h['x-powered-by'] ? `X-Powered-By: ${h['x-powered-by']}` : ''}`.trim(),
              'Facilitates automated vulnerability fingerprinting against known server CVEs.',
              true
            )
          );
        }
      }

      // 2. Cookie Security Audit
      if (config.checkCookies && pageResp.setCookies.length > 0) {
        for (const rawCookie of pageResp.setCookies) {
          const parsedCookie = parseSetCookieAttributes(rawCookie);
          if (!parsedCookie.hasHttpOnly) {
            rawFindings.push(
              buildFinding(
                pageId,
                'COOK-HTTPONLY-01',
                `Cookie "${parsedCookie.name}" Missing HttpOnly Attribute`,
                pageResp.finalUrl,
                parsedCookie.name,
                'High',
                'High',
                'A storefront or session cookie is set without the HttpOnly directive, making it readable by client-side JavaScript.',
                `Set-Cookie: ${rawCookie.split(';')[0]}; ... (HttpOnly absent)`,
                'If an XSS flaw occurs, attackers can read session tokens directly via document.cookie.',
                true
              )
            );
          }
          if (!parsedCookie.hasSecure) {
            rawFindings.push(
              buildFinding(
                pageId,
                'COOK-SECURE-01',
                `Cookie "${parsedCookie.name}" Missing Secure Attribute`,
                pageResp.finalUrl,
                parsedCookie.name,
                'High',
                'High',
                'A cookie is issued without the Secure flag, risking transmission over unencrypted HTTP.',
                `Set-Cookie: ${rawCookie.split(';')[0]}; ... (Secure absent)`,
                'Cookies may be intercepted on untrusted networks if an HTTP request is triggered.',
                true
              )
            );
          }
          if (!parsedCookie.hasSameSite) {
            rawFindings.push(
              buildFinding(
                pageId,
                'COOK-SAMESITE-01',
                `Cookie "${parsedCookie.name}" Missing SameSite Attribute`,
                pageResp.finalUrl,
                parsedCookie.name,
                'Medium',
                'High',
                'Cookie lacks an explicit SameSite=Lax or SameSite=Strict directive.',
                `Set-Cookie: ${rawCookie.split(';')[0]}; ... (SameSite absent)`,
                'Weakens cross-site request forgery protection across browsers.',
                true
              )
            );
          }
        }
      }

      // 3. Web & E-Commerce Misconfiguration Checks (CSRF, Mixed Content, Autocomplete, CORS)
      if (config.checkMisconfig) {
        if (pageResp.headers['access-control-allow-origin'] === '*' && pageResp.headers['access-control-allow-credentials'] === 'true') {
          rawFindings.push(
            buildFinding(
              pageId,
              'CORS-WILDCARD-01',
              'Permissive Cross-Origin Resource Sharing (CORS) Configuration',
              pageResp.finalUrl,
              'Access-Control-Allow-Origin',
              'Medium',
              'High',
              'CORS headers combine wildcard origin access with credential sharing.',
              'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
              'May permit unauthorized cross-origin reads of authenticated storefront responses.',
              true
            )
          );
        }

        if ($) {
          $('form').each((_idx, formEl) => {
            const method = ($(formEl).attr('method') || 'GET').toUpperCase();
            const action = $(formEl).attr('action') || pageResp.finalUrl;

            // Unencrypted HTTP form action on HTTPS page
            if (action.toLowerCase().startsWith('http://')) {
              rawFindings.push(
                buildFinding(
                  pageId,
                  'TRANS-HTTP-01',
                  'Insecure Cleartext HTTP Form Action Detected',
                  pageResp.finalUrl,
                  action,
                  'High',
                  'High',
                  'An e-commerce form submits customer data over unencrypted http:// instead of https://.',
                  `<form method="${method}" action="${action}">`,
                  'Customer credentials, shipping info, or card inputs may be exposed in transit.',
                  false
                )
              );
            }

            // Missing anti-CSRF token on POST forms
            if (method === 'POST') {
              const hasCsrfField = $(formEl)
                .find('input[type="hidden"]')
                .toArray()
                .some((inp) => /csrf|xsrf|token|nonce|authenticity/i.test($(inp).attr('name') || ''));

              if (!hasCsrfField) {
                rawFindings.push(
                  buildFinding(
                    pageId,
                    'CSRF-FORM-01',
                    'State-Changing POST Form Missing Anti-CSRF Token',
                    pageResp.finalUrl,
                    action,
                    'High',
                    'High',
                    'A POST form handling storefront state changes lacks a hidden anti-CSRF synchronizer token.',
                    `<form method="POST" action="${action}"> contains ${$(formEl).find('input').length} input(s) without CSRF token field.`,
                    'Attackers could craft cross-site requests to add items, alter account details, or initiate checkout actions.',
                    false
                  )
                );
              }
            }

            // Autocomplete on sensitive card/CVV fields
            $(formEl)
              .find('input')
              .each((_i, inpEl) => {
                const nameAttr = ($(inpEl).attr('name') || '').toLowerCase();
                const autoAttr = ($(inpEl).attr('autocomplete') || '').toLowerCase();
                if (/(card|cc_num|cvv|cvc|security_code)/i.test(nameAttr) && autoAttr !== 'off') {
                  rawFindings.push(
                    buildFinding(
                      pageId,
                      'AUTH-AUTOCOMPLETE-01',
                      'Browser Autocomplete Enabled on Payment Field',
                      pageResp.finalUrl,
                      nameAttr || 'payment_field',
                      'Low',
                      'High',
                      'Sensitive payment card or CVV input permits browser autocomplete caching.',
                      `<input name="${nameAttr}" autocomplete="${autoAttr || 'default'}">`,
                      'Shared or compromised workstations may retain sensitive payment input history.',
                      false
                    )
                  );
                }
              });
          });

          // Check inline scripts for risky DOM sinks
          if (config.checkXss) {
            const inlineScriptText = $('script:not([src])')
              .toArray()
              .map((s) => $(s).html() || '')
              .join('\n');
            const sinkMatch = inlineScriptText.match(/\b(innerHTML\s*=|document\.write\s*\(|eval\s*\()/);
            if (sinkMatch) {
              rawFindings.push(
                buildFinding(
                  pageId,
                  'XSS-DOM-01',
                  'Potentially Unsafe DOM Manipulation Sink in Inline Script',
                  pageResp.finalUrl,
                  sinkMatch[1].trim(),
                  'Medium',
                  'Medium',
                  'Client-side inline script uses a DOM sink capable of parsing raw HTML if fed untrusted data.',
                  `Matched sink pattern: "${sinkMatch[1].trim()}"`,
                  'If query parameters or hash fragments flow into this sink, DOM-based XSS can occur.',
                  false
                )
              );
            }
          }
        }
      }

      // 4. Controlled Non-Destructive XSS Reflection Check (benign alphanumeric probe)
      if (config.checkXss && !signal.aborted) {
        const probeToken = 'aegiscan739probe';
        const urlObj = new URL(pageResp.finalUrl);
        const paramsToTest = new Set<string>(Array.from(urlObj.searchParams.keys()));

        if ($) {
          $('form').each((_i, formEl) => {
            const method = ($(formEl).attr('method') || 'GET').toUpperCase();
            if (method === 'GET') {
              $(formEl)
                .find('input[name]')
                .each((_j, inp) => {
                  const n = $(inp).attr('name');
                  if (n) paramsToTest.add(n);
                });
            }
          });
        }

        for (const paramName of Array.from(paramsToTest).slice(0, 3)) {
          if (signal.aborted) break;
          const probeUrl = new URL(pageResp.finalUrl);
          probeUrl.searchParams.set(paramName, probeToken);
          try {
            const probeResp = await fetchTargetPage(probeUrl.toString(), validatedRoot.isDemoTarget, signal);
            const probeType = (probeResp.headers['content-type'] || '').toLowerCase();
            if (probeType.includes('text/html') && probeResp.body.includes(probeToken)) {
              // Confirm reflection occurs in visible HTML body, not solely inside an encoded attribute value
              const escapedRegex = new RegExp(`>[^<]*${probeToken}[^<]*<`, 'i');
              if (escapedRegex.test(probeResp.body)) {
                rawFindings.push(
                  buildFinding(
                    pageId,
                    'XSS-REFL-01',
                    'Unencoded Parameter Reflection (Reflected XSS Risk)',
                    pageResp.finalUrl,
                    paramName,
                    'High',
                    'High',
                    'A harmless alphanumeric probe parameter was reflected verbatim into the HTML document body without contextual encoding.',
                    `GET ${probeUrl.pathname}?${paramName}=${probeToken} reflected unencoded inside HTML body text.`,
                    'Untrusted characters submitted through this parameter may execute scripts in a shopper’s browser.',
                    false
                  )
                );
              }
            }
          } catch {
            // Ignore probe timeout
          }
        }
      }

      // 5. Non-Destructive SQL Error Disclosure / Input Validation Check
      if (config.checkSqli && !signal.aborted) {
        const urlObj = new URL(pageResp.finalUrl);
        const queryKeys = Array.from(urlObj.searchParams.keys());
        for (const paramName of queryKeys.slice(0, 2)) {
          if (signal.aborted) break;
          const probeUrl = new URL(pageResp.finalUrl);
          // Benign single-quote boundary character in read-only GET query
          probeUrl.searchParams.set(paramName, `'`);
          try {
            const probeResp = await fetchTargetPage(probeUrl.toString(), validatedRoot.isDemoTarget, signal);
            for (const sig of DB_ERROR_SIGNATURES) {
              const match = probeResp.body.match(sig.pattern);
              if (match) {
                rawFindings.push(
                  buildFinding(
                    pageId,
                    'SQLI-ERR-01',
                    `Verbose ${sig.engine} Database Error & SQL Injection Risk`,
                    pageResp.finalUrl,
                    paramName,
                    'Critical',
                    'High',
                    `A non-destructive syntax boundary probe on parameter "${paramName}" caused the backend to return an unhandled ${sig.engine} syntax exception.`,
                    `GET ${probeUrl.pathname}?${paramName}=' returned HTTP ${probeResp.status} matching "${match[0]}"`,
                    'Unhandled database syntax errors indicate unparameterized query construction vulnerable to data extraction.',
                    false
                  )
                );
                break;
              }
            }
          } catch {
            // Ignore probe network error
          }
        }
      }

      updateProgressStmt.run(pagesScanned, rawFindings.length, canonical, scanId);
    }

    // Check exposed config artifact on root (non-destructive 404 verification)
    if (config.checkMisconfig && !signal.aborted && pagesScanned > 0) {
      const envUrl = `${origin}/.env`;
      try {
        const envResp = await fetchTargetPage(envUrl, validatedRoot.isDemoTarget, signal);
        if (envResp.status === 200 && /APP_ENV=|DB_CONNECTION=|DB_PASSWORD=/i.test(envResp.body)) {
          rawFindings.push(
            buildFinding(
              null,
              'DISC-SENSITIVE-01',
              'Exposed Environment Configuration Artifact (/.env)',
              envUrl,
              '.env',
              'Critical',
              'High',
              'The web server serves an environment configuration file directly at /.env.',
              `GET /.env returned HTTP 200 containing configuration keys.`,
              'Environment files frequently expose database credentials, API keys, and signing secrets.',
              true
            )
          );
        }
      } catch {
        // Ignore if unreachable
      }
    }

    if (signal.aborted) {
      db.prepare(
        `UPDATE Scan_History SET status = 'stopped', pages_scanned = ?, completed_at = datetime('now'), current_url = '' WHERE id = ?`
      ).run(pagesScanned, scanId);
      return;
    }

    // Module 2: Run risk assessment & false-positive reduction
    const assessment = analyzeAndAssessRisk(rawFindings, pagesScanned);

    const insertVulnStmt = db.prepare(
      `INSERT INTO Vulnerabilities (
        scan_id, page_id, website_id, rule_code, name, category, affected_url, parameter_name,
        severity, confidence, description, evidence, potential_impact,
        owasp_top10, owasp_wstg, owasp_asvs, nist_800_115, remediation_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')`
    );

    const insertRecStmt = db.prepare(
      `INSERT INTO Security_Recommendations (
        vulnerability_id, rule_code, title, remediation_steps, preventive_measures,
        secure_coding_practice, code_example, priority
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const persistTx = db.transaction(() => {
      for (const f of assessment.validatedFindings) {
        const vRes = insertVulnStmt.run(
          scanId,
          f.page_id,
          config.websiteId,
          f.rule_code,
          f.name,
          f.category,
          f.affected_url,
          f.parameter_name,
          f.severity,
          f.confidence,
          f.description,
          f.evidence,
          f.potential_impact,
          f.owasp_top10,
          f.owasp_wstg,
          f.owasp_asvs,
          f.nist_800_115
        );
        const rec = getRecommendationForRule(f.rule_code);
        insertRecStmt.run(
          vRes.lastInsertRowid,
          rec.rule_code,
          rec.title,
          rec.remediation_steps,
          rec.preventive_measures,
          rec.secure_coding_practice,
          rec.code_example,
          rec.priority
        );
      }

      db.prepare(
        `INSERT INTO Risk_Assessments (
          scan_id, website_id, overall_score, risk_rating,
          critical_count, high_count, medium_count, low_count, false_positives_filtered,
          executive_summary, threat_actors_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        scanId,
        config.websiteId,
        assessment.overallScore,
        assessment.riskRating,
        assessment.criticalCount,
        assessment.highCount,
        assessment.mediumCount,
        assessment.lowCount,
        assessment.falsePositivesFiltered,
        assessment.executiveSummary,
        assessment.threatActorsSummary
      );

      db.prepare(
        `UPDATE Scan_History
         SET status = 'completed',
             pages_scanned = ?,
             vulnerabilities_found = ?,
             security_score = ?,
             current_url = '',
             completed_at = datetime('now')
         WHERE id = ?`
      ).run(pagesScanned, assessment.validatedFindings.length, assessment.overallScore, scanId);
    });

    persistTx();

    logAuditEvent({
      userId: config.userId,
      userEmail: config.userEmail,
      action: 'SCAN_COMPLETED',
      target: config.targetUrl,
      details: `Scan #${scanId} completed: ${pagesScanned} pages, ${assessment.validatedFindings.length} findings, score ${assessment.overallScore}/100`,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unexpected scanner error';
    if (signal.aborted) {
      db.prepare(
        `UPDATE Scan_History SET status = 'stopped', completed_at = datetime('now'), current_url = '' WHERE id = ?`
      ).run(scanId);
    } else {
      db.prepare(
        `UPDATE Scan_History SET status = 'failed', error_message = ?, completed_at = datetime('now'), current_url = '' WHERE id = ?`
      ).run(message, scanId);
      logAuditEvent({
        userId: config.userId,
        userEmail: config.userEmail,
        action: 'SCAN_FAILED',
        target: config.targetUrl,
        details: message,
      });
    }
  } finally {
    activeScanControllers.delete(scanId);
  }
}

export function getDemoUrl(): string {
  return DEMO_STORE_BASE_URL;
}
