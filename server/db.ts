import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const dataDir = path.resolve(process.cwd(), 'data');
fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, 'aegiscommerce.db');
export const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function initDatabase(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS Users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')) DEFAULT 'analyst',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_login_at TEXT
    );

    CREATE TABLE IF NOT EXISTS Sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Websites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT NOT NULL,
      base_url TEXT NOT NULL UNIQUE,
      domain TEXT NOT NULL,
      authorization_confirmed INTEGER NOT NULL DEFAULT 0,
      is_demo_target INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS Scan_History (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      website_id INTEGER NOT NULL,
      user_id INTEGER,
      status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'completed', 'stopped', 'failed')) DEFAULT 'queued',
      scan_mode TEXT NOT NULL DEFAULT 'standard',
      max_pages INTEGER NOT NULL DEFAULT 10,
      check_sqli INTEGER NOT NULL DEFAULT 1,
      check_xss INTEGER NOT NULL DEFAULT 1,
      check_headers INTEGER NOT NULL DEFAULT 1,
      check_cookies INTEGER NOT NULL DEFAULT 1,
      check_misconfig INTEGER NOT NULL DEFAULT 1,
      pages_scanned INTEGER NOT NULL DEFAULT 0,
      vulnerabilities_found INTEGER NOT NULL DEFAULT 0,
      security_score INTEGER DEFAULT NULL,
      current_url TEXT DEFAULT '',
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT,
      error_message TEXT,
      FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS Scanned_Pages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      http_status INTEGER NOT NULL,
      content_type TEXT NOT NULL DEFAULT 'text/html',
      response_time_ms INTEGER NOT NULL DEFAULT 0,
      forms_count INTEGER NOT NULL DEFAULT 0,
      inputs_count INTEGER NOT NULL DEFAULT 0,
      links_count INTEGER NOT NULL DEFAULT 0,
      headers_json TEXT NOT NULL DEFAULT '{}',
      cookies_json TEXT NOT NULL DEFAULT '[]',
      scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (scan_id) REFERENCES Scan_History(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      page_id INTEGER,
      website_id INTEGER NOT NULL,
      rule_code TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      affected_url TEXT NOT NULL,
      parameter_name TEXT DEFAULT '',
      severity TEXT NOT NULL CHECK(severity IN ('Critical', 'High', 'Medium', 'Low')),
      confidence TEXT NOT NULL CHECK(confidence IN ('High', 'Medium', 'Low')) DEFAULT 'High',
      description TEXT NOT NULL,
      evidence TEXT NOT NULL,
      potential_impact TEXT NOT NULL,
      owasp_top10 TEXT NOT NULL,
      owasp_wstg TEXT NOT NULL,
      owasp_asvs TEXT NOT NULL,
      nist_800_115 TEXT NOT NULL,
      remediation_status TEXT NOT NULL CHECK(remediation_status IN ('Open', 'In Progress', 'Resolved', 'Accepted Risk')) DEFAULT 'Open',
      detected_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (scan_id) REFERENCES Scan_History(id) ON DELETE CASCADE,
      FOREIGN KEY (page_id) REFERENCES Scanned_Pages(id) ON DELETE SET NULL,
      FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Risk_Assessments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL UNIQUE,
      website_id INTEGER NOT NULL,
      overall_score INTEGER NOT NULL,
      risk_rating TEXT NOT NULL CHECK(risk_rating IN ('Critical', 'High', 'Moderate', 'Low')),
      critical_count INTEGER NOT NULL DEFAULT 0,
      high_count INTEGER NOT NULL DEFAULT 0,
      medium_count INTEGER NOT NULL DEFAULT 0,
      low_count INTEGER NOT NULL DEFAULT 0,
      false_positives_filtered INTEGER NOT NULL DEFAULT 0,
      executive_summary TEXT NOT NULL,
      threat_actors_summary TEXT NOT NULL,
      assessed_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (scan_id) REFERENCES Scan_History(id) ON DELETE CASCADE,
      FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Security_Recommendations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vulnerability_id INTEGER NOT NULL UNIQUE,
      rule_code TEXT NOT NULL,
      title TEXT NOT NULL,
      remediation_steps TEXT NOT NULL,
      preventive_measures TEXT NOT NULL,
      secure_coding_practice TEXT NOT NULL,
      code_example TEXT NOT NULL,
      priority TEXT NOT NULL CHECK(priority IN ('Immediate', 'High', 'Medium', 'Low')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (vulnerability_id) REFERENCES Vulnerabilities(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Generated_Reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      website_id INTEGER NOT NULL,
      user_id INTEGER,
      report_title TEXT NOT NULL,
      format TEXT NOT NULL CHECK(format IN ('PDF', 'CSV')),
      vulnerability_count INTEGER NOT NULL DEFAULT 0,
      security_score INTEGER NOT NULL DEFAULT 0,
      generated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (scan_id) REFERENCES Scan_History(id) ON DELETE CASCADE,
      FOREIGN KEY (website_id) REFERENCES Websites(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS Audit_Logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      user_email TEXT,
      action TEXT NOT NULL,
      target TEXT,
      details TEXT,
      ip_address TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS Demo_Store_Config (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      posture TEXT NOT NULL CHECK(posture IN ('vulnerable', 'hardened')) DEFAULT 'vulnerable',
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  db.prepare(`INSERT OR IGNORE INTO Demo_Store_Config (id, posture) VALUES (1, 'vulnerable')`).run();
  seedSampleDataset();
}

export function logAuditEvent(params: {
  userId?: number | null;
  userEmail?: string | null;
  action: string;
  target?: string;
  details?: string;
  ipAddress?: string;
}): void {
  db.prepare(
    `INSERT INTO Audit_Logs (user_id, user_email, action, target, details, ip_address)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    params.userId ?? null,
    params.userEmail ?? null,
    params.action,
    params.target ?? null,
    params.details ?? null,
    params.ipAddress ?? null
  );
}

function seedSampleDataset(): void {
  const existingWebsites = db.prepare('SELECT COUNT(*) as count FROM Websites').get() as { count: number };
  if (existingWebsites.count > 0) {
    return;
  }

  const insertWebsite = db.prepare(
    `INSERT INTO Websites (user_id, name, base_url, domain, authorization_confirmed, is_demo_target, created_at)
     VALUES (NULL, ?, ?, ?, 1, ?, ?)`
  );

  const demoSite = insertWebsite.run(
    'Meridian Mart (Demo Store)',
    'https://demo-store.aegiscommerce.test',
    'demo-store.aegiscommerce.test',
    1,
    '2026-11-18 09:15:00'
  );
  const nordicSite = insertWebsite.run(
    'NordicGear Apparel Staging',
    'https://staging.nordicgear-commerce.example',
    'staging.nordicgear-commerce.example',
    0,
    '2026-11-19 14:20:00'
  );
  const artisanalSite = insertWebsite.run(
    'Artisanal Roast Roasters',
    'https://shop.artisanalroast.example',
    'shop.artisanalroast.example',
    0,
    '2026-11-21 11:05:00'
  );

  const insertScan = db.prepare(
    `INSERT INTO Scan_History (
      website_id, user_id, status, scan_mode, max_pages,
      check_sqli, check_xss, check_headers, check_cookies, check_misconfig,
      pages_scanned, vulnerabilities_found, security_score, current_url, started_at, completed_at
    ) VALUES (?, NULL, 'completed', ?, 10, 1, 1, 1, 1, 1, ?, ?, ?, '', ?, ?)`
  );

  const scan1 = insertScan.run(
    demoSite.lastInsertRowid,
    'comprehensive',
    7,
    7,
    36,
    '2026-11-18 09:20:00',
    '2026-11-18 09:20:14'
  );
  const scan2 = insertScan.run(
    nordicSite.lastInsertRowid,
    'standard',
    8,
    5,
    64,
    '2026-11-19 14:25:00',
    '2026-11-19 14:25:18'
  );
  const scan3 = insertScan.run(
    nordicSite.lastInsertRowid,
    'comprehensive',
    8,
    3,
    82,
    '2026-11-21 16:40:00',
    '2026-11-21 16:40:15'
  );
  const scan4 = insertScan.run(
    artisanalSite.lastInsertRowid,
    'standard',
    6,
    2,
    89,
    '2026-11-22 10:12:00',
    '2026-11-22 10:12:11'
  );

  const insertPage = db.prepare(
    `INSERT INTO Scanned_Pages (scan_id, url, http_status, content_type, response_time_ms, forms_count, inputs_count, links_count, headers_json, cookies_json, scanned_at)
     VALUES (?, ?, 200, 'text/html; charset=utf-8', ?, ?, ?, ?, ?, ?, ?)`
  );

  const demoHomePage = insertPage.run(
    scan1.lastInsertRowid,
    'https://demo-store.aegiscommerce.test/',
    42,
    1,
    2,
    6,
    JSON.stringify({ server: 'Apache/2.4.49 (Unix)', 'content-type': 'text/html; charset=utf-8' }),
    JSON.stringify(['meridian_sid=sample_session; Path=/']),
    '2026-11-18 09:20:03'
  );
  const demoProductPage = insertPage.run(
    scan1.lastInsertRowid,
    'https://demo-store.aegiscommerce.test/product?id=101',
    55,
    1,
    2,
    5,
    JSON.stringify({ server: 'Apache/2.4.49 (Unix)', 'content-type': 'text/html; charset=utf-8' }),
    JSON.stringify([]),
    '2026-11-18 09:20:05'
  );
  const demoSearchPage = insertPage.run(
    scan1.lastInsertRowid,
    'https://demo-store.aegiscommerce.test/search?q=coffee',
    48,
    1,
    1,
    4,
    JSON.stringify({ server: 'Apache/2.4.49 (Unix)', 'content-type': 'text/html; charset=utf-8' }),
    JSON.stringify([]),
    '2026-11-18 09:20:07'
  );
  const demoCheckoutPage = insertPage.run(
    scan1.lastInsertRowid,
    'https://demo-store.aegiscommerce.test/checkout',
    63,
    1,
    6,
    3,
    JSON.stringify({ server: 'Apache/2.4.49 (Unix)', 'content-type': 'text/html; charset=utf-8' }),
    JSON.stringify([]),
    '2026-11-18 09:20:10'
  );

  const nordicCheckout = insertPage.run(
    scan2.lastInsertRowid,
    'https://staging.nordicgear-commerce.example/checkout',
    118,
    1,
    5,
    4,
    JSON.stringify({ 'x-content-type-options': 'nosniff' }),
    JSON.stringify(['ng_cart=8821; Path=/; Secure']),
    '2026-11-19 14:25:10'
  );

  const nordicRescanPage = insertPage.run(
    scan3.lastInsertRowid,
    'https://staging.nordicgear-commerce.example/checkout',
    92,
    1,
    5,
    4,
    JSON.stringify({
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
    }),
    JSON.stringify(['ng_cart=8821; Path=/; Secure; HttpOnly; SameSite=Lax']),
    '2026-11-21 16:40:09'
  );

  const artisanalHome = insertPage.run(
    scan4.lastInsertRowid,
    'https://shop.artisanalroast.example/',
    74,
    1,
    1,
    9,
    JSON.stringify({
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'SAMEORIGIN',
    }),
    JSON.stringify(['ar_session=abc; Path=/; Secure; HttpOnly; SameSite=Lax']),
    '2026-11-22 10:12:04'
  );

  const insertVuln = db.prepare(
    `INSERT INTO Vulnerabilities (
      scan_id, page_id, website_id, rule_code, name, category, affected_url, parameter_name,
      severity, confidence, description, evidence, potential_impact,
      owasp_top10, owasp_wstg, owasp_asvs, nist_800_115, remediation_status, detected_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const insertRec = db.prepare(
    `INSERT INTO Security_Recommendations (
      vulnerability_id, rule_code, title, remediation_steps, preventive_measures,
      secure_coding_practice, code_example, priority
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const seedFinding = (
    scanId: number | bigint,
    pageId: number | bigint,
    websiteId: number | bigint,
    ruleCode: string,
    name: string,
    category: string,
    url: string,
    param: string,
    severity: 'Critical' | 'High' | 'Medium' | 'Low',
    confidence: 'High' | 'Medium' | 'Low',
    desc: string,
    evidence: string,
    impact: string,
    owasp10: string,
    wstg: string,
    asvs: string,
    nist: string,
    status: 'Open' | 'In Progress' | 'Resolved' | 'Accepted Risk',
    detectedAt: string,
    recTitle: string,
    steps: string,
    preventive: string,
    coding: string,
    codeEx: string,
    priority: 'Immediate' | 'High' | 'Medium' | 'Low'
  ) => {
    const v = insertVuln.run(
      scanId, pageId, websiteId, ruleCode, name, category, url, param,
      severity, confidence, desc, evidence, impact, owasp10, wstg, asvs, nist, status, detectedAt
    );
    insertRec.run(v.lastInsertRowid, ruleCode, recTitle, steps, preventive, coding, codeEx, priority);
  };

  // Seed Demo Store findings (Scan 1)
  seedFinding(
    scan1.lastInsertRowid, demoProductPage.lastInsertRowid, demoSite.lastInsertRowid,
    'SQLI-ERR-01',
    'Verbose Database Error Disclosure & Potential SQL Injection Risk',
    'Injection',
    'https://demo-store.aegiscommerce.test/product?id=101',
    'id',
    'Critical',
    'High',
    'Submitting a non-destructive syntax boundary probe to the product identifier parameter triggered a raw SQLite query syntax exception in the HTTP response.',
    'GET /product?id=\' returned HTTP 500 signature: "SQLITE_ERROR: near \\"\\\'\\": syntax error in SELECT * FROM products WHERE id = \'\'\'"',
    'Unparameterized query handling can allow attackers to manipulate backend SQL queries, read customer PII, modify product pricing, or bypass authentication.',
    'A03:2021 - Injection',
    'WSTG-INPV-05',
    'ASVS V5.3.4',
    'NIST SP 800-115 §6.2',
    'Open',
    '2026-11-18 09:20:05',
    'Enforce Parameterized Queries & Suppress Raw DB Errors',
    '1. Replace string-concatenated SQL with parameterized prepared statements.\n2. Cast and validate numeric route/query IDs against strict integer schemas.\n3. Configure global exception handlers to log errors server-side and return generic 400/404 responses.',
    'Adopt an ORM or query builder with strict bind-parameter enforcement and run SAST checks in CI/CD.',
    'Never interpolate request parameters into SQL strings. Validate input types before database access.',
    'const stmt = db.prepare("SELECT id, name, price FROM products WHERE id = ?");\nconst product = stmt.get(Number(req.query.id));',
    'Immediate'
  );

  seedFinding(
    scan1.lastInsertRowid, demoSearchPage.lastInsertRowid, demoSite.lastInsertRowid,
    'XSS-REFL-01',
    'Unencoded Query Reflection (Reflected Cross-Site Scripting Risk)',
    'Cross-Site Scripting (XSS)',
    'https://demo-store.aegiscommerce.test/search?q=coffee',
    'q',
    'High',
    'High',
    'A harmless alphanumeric reflection probe submitted to the store search field was echoed verbatim into an HTML heading without contextual output encoding.',
    'Probe "aegiscan739probe" reflected unencoded inside <h2>Results for: aegiscan739probe</h2> without Content-Security-Policy protection.',
    'An attacker could craft malicious storefront links to execute arbitrary scripts in shoppers’ browsers, stealing session tokens or skimming checkout inputs.',
    'A03:2021 - Injection',
    'WSTG-INPV-01',
    'ASVS V5.3.3',
    'NIST SP 800-115 §6.2',
    'Open',
    '2026-11-18 09:20:07',
    'Apply Context-Aware HTML Output Encoding & Strict CSP',
    '1. Encode all user-supplied search strings using context-appropriate HTML entity escaping before rendering.\n2. Deploy a restrictive Content-Security-Policy header prohibiting inline script execution.',
    'Use auto-escaping templating engines or React JSX text bindings; avoid raw HTML injection sinks.',
    'Sanitize input length/characters and escape &, <, >, ", and \' when rendering into HTML contexts.',
    'res.setHeader("Content-Security-Policy", "default-src \'self\'; script-src \'self\'");\nconst safeQuery = escapeHtml(String(req.query.q ?? ""));',
    'High'
  );

  seedFinding(
    scan1.lastInsertRowid, demoCheckoutPage.lastInsertRowid, demoSite.lastInsertRowid,
    'CSRF-FORM-01',
    'Missing Anti-CSRF Protection on Checkout Form',
    'Broken Access Control',
    'https://demo-store.aegiscommerce.test/checkout',
    'checkout_form',
    'High',
    'High',
    'The state-changing POST checkout form lacks an anti-CSRF synchronizer token or verifiable SameSite cookie enforcement.',
    '<form method="POST" action="/checkout"> contains 6 inputs without hidden csrf_token / _csrf field.',
    'Authenticated shoppers lured to third-party pages could be forced to submit unauthorized orders or shipping address changes.',
    'A01:2021 - Broken Access Control',
    'WSTG-SESS-05',
    'ASVS V4.2.2',
    'NIST SP 800-115 §6.3',
    'Open',
    '2026-11-18 09:20:10',
    'Implement Cryptographic Anti-CSRF Tokens & SameSite Cookies',
    '1. Generate a per-session CSPRNG CSRF token and embed it as a hidden input on all state-changing forms.\n2. Validate the submitted token on the server using constant-time comparison.\n3. Enforce SameSite=Lax or Strict on session cookies.',
    'Protect every POST/PUT/DELETE endpoint with server-side CSRF middleware and Origin header verification.',
    'Verify Origin/Referer headers alongside anti-CSRF tokens for payment and account endpoints.',
    '<input type="hidden" name="_csrf" value="{{csrfToken}}" />',
    'High'
  );

  seedFinding(
    scan1.lastInsertRowid, demoHomePage.lastInsertRowid, demoSite.lastInsertRowid,
    'COOK-HTTPONLY-01',
    'Session Cookie Missing HttpOnly, Secure & SameSite Flags',
    'Session Management',
    'https://demo-store.aegiscommerce.test/',
    'meridian_sid',
    'High',
    'High',
    'The primary storefront session cookie is issued without HttpOnly, Secure, or SameSite attributes.',
    'Set-Cookie: meridian_sid=sample_session; Path=/ (missing HttpOnly, Secure, SameSite)',
    'Client-side scripts can read the session identifier via document.cookie, and unencrypted HTTP connections expose the token to network interception.',
    'A02:2021 - Cryptographic Failures',
    'WSTG-SESS-02',
    'ASVS V3.4.1',
    'NIST SP 800-115 §5.2',
    'Open',
    '2026-11-18 09:20:03',
    'Harden Session Cookie Attributes',
    '1. Add HttpOnly to block client-side JavaScript access.\n2. Add Secure to restrict transmission to HTTPS.\n3. Set SameSite=Lax or SameSite=Strict.',
    'Centralize cookie creation in a single hardened helper function.',
    'Audit all Set-Cookie headers across login, cart, and checkout routes.',
    'res.cookie("meridian_sid", token, { httpOnly: true, secure: true, sameSite: "strict", path: "/" });',
    'High'
  );

  seedFinding(
    scan1.lastInsertRowid, demoHomePage.lastInsertRowid, demoSite.lastInsertRowid,
    'HDR-CSP-01',
    'Missing Content-Security-Policy (CSP) Header',
    'Security Misconfiguration',
    'https://demo-store.aegiscommerce.test/',
    'Content-Security-Policy',
    'Medium',
    'High',
    'Responses omit the Content-Security-Policy header, leaving storefront pages without browser-level script and frame origin restrictions.',
    'HTTP Response Headers missing "content-security-policy".',
    'Increases blast radius of XSS or third-party checkout script tampering (Magecart-style payment skimming).',
    'A05:2021 - Security Misconfiguration',
    'WSTG-CONF-07',
    'ASVS V14.4.3',
    'NIST SP 800-115 §5.2',
    'Open',
    '2026-11-18 09:20:03',
    'Deploy Restrictive Content-Security-Policy Header',
    '1. Define default-src \'self\' and explicit allowlists for payment/analytics scripts.\n2. Set frame-ancestors \'none\' and object-src \'none\'.\n3. Test with Content-Security-Policy-Report-Only before enforcement.',
    'Use Subresource Integrity (SRI) for external scripts alongside CSP.',
    'Configure Helmet or reverse-proxy security headers globally.',
    'Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\';',
    'Medium'
  );

  seedFinding(
    scan1.lastInsertRowid, demoHomePage.lastInsertRowid, demoSite.lastInsertRowid,
    'HDR-HSTS-01',
    'Missing HTTP Strict-Transport-Security (HSTS) Header',
    'Cryptographic Failures',
    'https://demo-store.aegiscommerce.test/',
    'Strict-Transport-Security',
    'Medium',
    'High',
    'HTTPS responses do not advertise Strict-Transport-Security to enforce TLS-only browser connections.',
    'HTTP Response Headers missing "strict-transport-security".',
    'First-visit HTTP requests may be susceptible to SSL-stripping downgrade attacks on public Wi-Fi.',
    'A02:2021 - Cryptographic Failures',
    'WSTG-CRYP-01',
    'ASVS V9.1.1',
    'NIST SP 800-115 §5.2',
    'Open',
    '2026-11-18 09:20:03',
    'Enable HSTS Across All Subdomains',
    '1. Emit Strict-Transport-Security with max-age of at least 31536000 seconds.\n2. Include includeSubDomains once all subdomains support HTTPS.',
    'Redirect all port 80 HTTP traffic to port 443 HTTPS permanently.',
    'Verify TLS certificates and cipher suites quarterly.',
    'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    'Medium'
  );

  seedFinding(
    scan1.lastInsertRowid, demoHomePage.lastInsertRowid, demoSite.lastInsertRowid,
    'HDR-INFO-01',
    'Server Technology Version Banner Exposed',
    'Security Misconfiguration',
    'https://demo-store.aegiscommerce.test/',
    'Server',
    'Low',
    'High',
    'The HTTP Server response header discloses exact web server software and patch version details.',
    'Header observed: Server: Apache/2.4.49 (Unix)',
    'Helps automated reconnaissance tools fingerprint exact server versions for known CVE matching.',
    'A05:2021 - Security Misconfiguration',
    'WSTG-INFO-02',
    'ASVS V14.3.3',
    'NIST SP 800-115 §5.1',
    'Open',
    '2026-11-18 09:20:03',
    'Suppress Detailed Server & Framework Banners',
    '1. Configure Apache ServerTokens Prod and ServerSignature Off (or remove X-Powered-By in Express/Flask).\n2. Strip internal backend version headers at the edge proxy.',
    'Standardize hardened server templates for all production deployments.',
    'Never expose stack traces or framework versions in HTTP headers.',
    'app.disable("x-powered-by");',
    'Low'
  );

  // Seed Scan 2 (NordicGear baseline) & Scan 3 (NordicGear after partial remediation)
  seedFinding(
    scan2.lastInsertRowid, nordicCheckout.lastInsertRowid, nordicSite.lastInsertRowid,
    'HDR-CSP-01',
    'Missing Content-Security-Policy (CSP) Header',
    'Security Misconfiguration',
    'https://staging.nordicgear-commerce.example/checkout',
    'Content-Security-Policy',
    'Medium',
    'High',
    'Checkout and storefront pages do not return a Content-Security-Policy header.',
    'Response headers omitted content-security-policy.',
    'Weakens defense-in-depth against unauthorized third-party payment scripts.',
    'A05:2021 - Security Misconfiguration',
    'WSTG-CONF-07',
    'ASVS V14.4.3',
    'NIST SP 800-115 §5.2',
    'Resolved',
    '2026-11-19 14:25:10',
    'Deploy Content-Security-Policy Header',
    '1. Configure strict CSP directives at the gateway.',
    'Review third-party script allowlists monthly.',
    'Restrict script-src and frame-ancestors.',
    'Content-Security-Policy: default-src \'self\'; frame-ancestors \'none\';',
    'Medium'
  );

  seedFinding(
    scan2.lastInsertRowid, nordicCheckout.lastInsertRowid, nordicSite.lastInsertRowid,
    'COOK-HTTPONLY-01',
    'Cart Session Cookie Missing HttpOnly & SameSite Flags',
    'Session Management',
    'https://staging.nordicgear-commerce.example/checkout',
    'ng_cart',
    'High',
    'High',
    'Cart cookie includes Secure flag but omits HttpOnly and SameSite.',
    'Set-Cookie: ng_cart=8821; Path=/; Secure',
    'Exposes cart/session identifier to potential client-side script reads.',
    'A02:2021 - Cryptographic Failures',
    'WSTG-SESS-02',
    'ASVS V3.4.1',
    'NIST SP 800-115 §5.2',
    'Resolved',
    '2026-11-19 14:25:10',
    'Add HttpOnly and SameSite=Lax to Cart Cookie',
    '1. Update session middleware cookie options to set httpOnly: true and sameSite: "lax".',
    'Validate cookie flags in integration tests.',
    'Use Secure, HttpOnly, and SameSite across all session cookies.',
    'Set-Cookie: ng_cart=8821; Path=/; Secure; HttpOnly; SameSite=Lax',
    'High'
  );

  seedFinding(
    scan3.lastInsertRowid, nordicRescanPage.lastInsertRowid, nordicSite.lastInsertRowid,
    'HDR-REF-01',
    'Missing Referrer-Policy Header',
    'Security Misconfiguration',
    'https://staging.nordicgear-commerce.example/checkout',
    'Referrer-Policy',
    'Low',
    'High',
    'Pages do not set Referrer-Policy, potentially leaking order confirmation URLs to external analytics endpoints.',
    'HTTP Response Headers missing "referrer-policy".',
    'External links clicked from account/order pages may transmit query parameters in the Referer header.',
    'A05:2021 - Security Misconfiguration',
    'WSTG-CONF-07',
    'ASVS V14.4.6',
    'NIST SP 800-115 §5.2',
    'In Progress',
    '2026-11-21 16:40:09',
    'Set Strict Referrer-Policy Header',
    '1. Emit Referrer-Policy: strict-origin-when-cross-origin on all HTML responses.',
    'Avoid placing sensitive identifiers in URL query strings.',
    'Combine Referrer-Policy with rel="noopener noreferrer" on external links.',
    'Referrer-Policy: strict-origin-when-cross-origin',
    'Low'
  );

  seedFinding(
    scan4.lastInsertRowid, artisanalHome.lastInsertRowid, artisanalSite.lastInsertRowid,
    'HDR-CSP-01',
    'Missing Content-Security-Policy (CSP) Header',
    'Security Misconfiguration',
    'https://shop.artisanalroast.example/',
    'Content-Security-Policy',
    'Medium',
    'High',
    'Storefront lacks Content-Security-Policy enforcement.',
    'HTTP Response Headers missing "content-security-policy".',
    'Reduces browser-enforced mitigation against cross-site script injection.',
    'A05:2021 - Security Misconfiguration',
    'WSTG-CONF-07',
    'ASVS V14.4.3',
    'NIST SP 800-115 §5.2',
    'Open',
    '2026-11-22 10:12:04',
    'Deploy Content-Security-Policy Header',
    '1. Configure default-src \'self\' and script-src allowlist.',
    'Monitor CSP violation reports.',
    'Disallow unsafe-inline and unsafe-eval.',
    'Content-Security-Policy: default-src \'self\'; script-src \'self\';',
    'Medium'
  );

  const insertRisk = db.prepare(
    `INSERT INTO Risk_Assessments (
      scan_id, website_id, overall_score, risk_rating,
      critical_count, high_count, medium_count, low_count, false_positives_filtered,
      executive_summary, threat_actors_summary, assessed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  insertRisk.run(
    scan1.lastInsertRowid, demoSite.lastInsertRowid, 36, 'Critical',
    1, 3, 2, 1, 2,
    'Meridian Mart (Demo Store) exhibits critical injection and session-handling gaps across checkout and search endpoints. Immediate remediation of parameterized queries, CSRF tokens, and cookie flags is required.',
    'Primary threats include automated SQL error harvesting, reflected XSS session theft, and checkout CSRF tampering.',
    '2026-11-18 09:20:14'
  );
  insertRisk.run(
    scan2.lastInsertRowid, nordicSite.lastInsertRowid, 64, 'High',
    0, 1, 1, 0, 1,
    'Initial staging scan of NordicGear Apparel identified missing CSP and incomplete session cookie protections on checkout routes.',
    'Opportunistic client-side script skimming and session exposure risks.',
    '2026-11-19 14:25:18'
  );
  insertRisk.run(
    scan3.lastInsertRowid, nordicSite.lastInsertRowid, 82, 'Low',
    0, 0, 0, 1, 1,
    'Rescan verified remediation of cookie attributes, HSTS, and X-Frame-Options. Only minor Referrer-Policy hardening remains.',
    'Minimal residual exposure; maintain continuous regression scanning.',
    '2026-11-21 16:40:15'
  );
  insertRisk.run(
    scan4.lastInsertRowid, artisanalSite.lastInsertRowid, 89, 'Low',
    0, 0, 1, 0, 0,
    'Artisanal Roast Roasters demonstrates strong cookie and transport security; deploying CSP will raise the posture above 95.',
    'Low risk of script injection due to solid framework defaults; CSP recommended for defense-in-depth.',
    '2026-11-22 10:12:11'
  );

  const insertReport = db.prepare(
    `INSERT INTO Generated_Reports (scan_id, website_id, user_id, report_title, format, vulnerability_count, security_score, generated_at)
     VALUES (?, ?, NULL, ?, ?, ?, ?, ?)`
  );
  insertReport.run(scan1.lastInsertRowid, demoSite.lastInsertRowid, 'Meridian Mart Baseline Security Audit', 'PDF', 7, 36, '2026-11-18 09:22:00');
  insertReport.run(scan3.lastInsertRowid, nordicSite.lastInsertRowid, 'NordicGear Post-Remediation Rescan Export', 'CSV', 1, 82, '2026-11-21 16:45:00');
}
