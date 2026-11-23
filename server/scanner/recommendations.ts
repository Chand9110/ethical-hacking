export interface RecommendationRule {
  rule_code: string;
  title: string;
  category: string;
  default_severity: 'Critical' | 'High' | 'Medium' | 'Low';
  owasp_top10: string;
  owasp_wstg: string;
  owasp_asvs: string;
  nist_800_115: string;
  remediation_steps: string;
  preventive_measures: string;
  secure_coding_practice: string;
  code_example: string;
  priority: 'Immediate' | 'High' | 'Medium' | 'Low';
}

export const RECOMMENDATION_LIBRARY: Record<string, RecommendationRule> = {
  'SQLI-ERR-01': {
    rule_code: 'SQLI-ERR-01',
    title: 'Enforce Parameterized Queries & Suppress Verbose DB Errors',
    category: 'Injection',
    default_severity: 'Critical',
    owasp_top10: 'A03:2021 - Injection',
    owasp_wstg: 'WSTG-INPV-05',
    owasp_asvs: 'ASVS V5.3.4',
    nist_800_115: 'NIST SP 800-115 §6.2',
    remediation_steps:
      '1. Convert all dynamic SQL queries to parameterized prepared statements.\n2. Validate numeric IDs and sort keys against strict allowlists before executing queries.\n3. Replace raw stack traces or database exceptions with generic HTTP 400/500 responses.',
    preventive_measures:
      'Use an ORM or strict query builder with lint rules banning string interpolation in SQL calls, and run automated SAST scans in CI.',
    secure_coding_practice:
      'Separate code from data using bound parameters; apply least-privilege database user permissions for storefront reads vs admin writes.',
    code_example:
      'const stmt = db.prepare("SELECT id, name, price FROM products WHERE id = ?");\nconst item = stmt.get(Number(req.query.id));',
    priority: 'Immediate',
  },
  'XSS-REFL-01': {
    rule_code: 'XSS-REFL-01',
    title: 'Apply Contextual Output Encoding & Restrictive CSP',
    category: 'Cross-Site Scripting (XSS)',
    default_severity: 'High',
    owasp_top10: 'A03:2021 - Injection',
    owasp_wstg: 'WSTG-INPV-01',
    owasp_asvs: 'ASVS V5.3.3',
    nist_800_115: 'NIST SP 800-115 §6.2',
    remediation_steps:
      '1. Escape user-controlled query parameters according to their output context (HTML body, attribute, JS, URL).\n2. Enforce a Content-Security-Policy blocking inline scripts and untrusted third-party domains.',
    preventive_measures:
      'Rely on auto-escaping template engines (React JSX, Jinja2 autoescape) and prohibit raw HTML rendering sinks for user input.',
    secure_coding_practice:
      'Validate input format at entry and encode output right before rendering into HTML templates.',
    code_example:
      'const safeQuery = escapeHtml(String(req.query.q ?? ""));\nres.setHeader("Content-Security-Policy", "default-src \'self\'; script-src \'self\'");',
    priority: 'High',
  },
  'XSS-DOM-01': {
    rule_code: 'XSS-DOM-01',
    title: 'Eliminate Unsafe DOM Sinks in Client Storefront Scripts',
    category: 'Cross-Site Scripting (XSS)',
    default_severity: 'Medium',
    owasp_top10: 'A03:2021 - Injection',
    owasp_wstg: 'WSTG-CLNT-01',
    owasp_asvs: 'ASVS V5.3.6',
    nist_800_115: 'NIST SP 800-115 §6.2',
    remediation_steps:
      '1. Replace innerHTML, outerHTML, and document.write calls with textContent or safe DOM APIs.\n2. Sanitize any unavoidable rich HTML fragments with DOMPurify.',
    preventive_measures:
      'Enable ESLint security rules (no-unsanitized) and Trusted Types in Content-Security-Policy.',
    secure_coding_practice:
      'Prefer declarative framework state bindings over imperative DOM manipulation.',
    code_example:
      'element.textContent = searchQuery; // Safe text binding instead of element.innerHTML = searchQuery',
    priority: 'Medium',
  },
  'CSRF-FORM-01': {
    rule_code: 'CSRF-FORM-01',
    title: 'Add Anti-CSRF Tokens to State-Changing E-Commerce Forms',
    category: 'Broken Access Control',
    default_severity: 'High',
    owasp_top10: 'A01:2021 - Broken Access Control',
    owasp_wstg: 'WSTG-SESS-05',
    owasp_asvs: 'ASVS V4.2.2',
    nist_800_115: 'NIST SP 800-115 §6.3',
    remediation_steps:
      '1. Generate a cryptographically random anti-CSRF token bound to the user session.\n2. Include it as a hidden form field on login, cart, profile, and checkout forms.\n3. Verify the token on every POST/PUT/DELETE request.',
    preventive_measures:
      'Pair synchronizer tokens with SameSite=Lax/Strict cookies and Origin header validation.',
    secure_coding_practice:
      'Never use GET requests for state mutations such as adding items to cart, changing addresses, or placing orders.',
    code_example:
      '<form method="POST" action="/checkout">\n  <input type="hidden" name="_csrf" value="{{csrfToken}}" />\n</form>',
    priority: 'High',
  },
  'COOK-HTTPONLY-01': {
    rule_code: 'COOK-HTTPONLY-01',
    title: 'Set HttpOnly Flag on Session & Authentication Cookies',
    category: 'Session Management',
    default_severity: 'High',
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    owasp_wstg: 'WSTG-SESS-02',
    owasp_asvs: 'ASVS V3.4.2',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Configure session cookie attributes to include HttpOnly.\n2. Verify document.cookie cannot read authentication or cart session identifiers.',
    preventive_measures:
      'Centralize cookie issuance inside a hardened server utility.',
    secure_coding_practice:
      'Keep session identifiers inaccessible to browser JavaScript to limit impact of any client-side script flaw.',
    code_example:
      'res.cookie("session_id", token, { httpOnly: true, secure: true, sameSite: "strict" });',
    priority: 'High',
  },
  'COOK-SECURE-01': {
    rule_code: 'COOK-SECURE-01',
    title: 'Enforce Secure Flag on Cookies Over HTTPS',
    category: 'Session Management',
    default_severity: 'High',
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    owasp_wstg: 'WSTG-SESS-02',
    owasp_asvs: 'ASVS V3.4.1',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Add the Secure directive to every Set-Cookie header carrying session or user state.\n2. Serve all storefront pages exclusively over HTTPS.',
    preventive_measures:
      'Combine Secure cookies with HSTS so browsers never transmit cookies over cleartext HTTP.',
    secure_coding_practice:
      'Ensure production web framework config sets SESSION_COOKIE_SECURE = True.',
    code_example:
      'Set-Cookie: sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax',
    priority: 'High',
  },
  'COOK-SAMESITE-01': {
    rule_code: 'COOK-SAMESITE-01',
    title: 'Configure SameSite Attribute on Storefront Cookies',
    category: 'Session Management',
    default_severity: 'Medium',
    owasp_top10: 'A01:2021 - Broken Access Control',
    owasp_wstg: 'WSTG-SESS-02',
    owasp_asvs: 'ASVS V3.4.3',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Set SameSite=Lax (or SameSite=Strict for sensitive checkout/admin sessions) on all session cookies.',
    preventive_measures:
      'Review third-party payment gateway redirect flows to ensure compatibility with SameSite=Lax.',
    secure_coding_practice:
      'Explicitly define SameSite rather than relying on browser defaults.',
    code_example:
      'Set-Cookie: sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict',
    priority: 'Medium',
  },
  'HDR-CSP-01': {
    rule_code: 'HDR-CSP-01',
    title: 'Deploy Restrictive Content-Security-Policy (CSP) Header',
    category: 'Security Misconfiguration',
    default_severity: 'Medium',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-CONF-07',
    owasp_asvs: 'ASVS V14.4.3',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Define a CSP header restricting script-src, style-src, connect-src, and frame-ancestors.\n2. Remove unsafe-inline and unsafe-eval directives.\n3. Monitor violation reports on checkout pages to detect unauthorized scripts.',
    preventive_measures:
      'Maintain an allowlist of approved payment SDKs with Subresource Integrity (SRI).',
    secure_coding_practice:
      'Apply CSP globally via middleware or reverse proxy headers.',
    code_example:
      'Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\';',
    priority: 'Medium',
  },
  'HDR-HSTS-01': {
    rule_code: 'HDR-HSTS-01',
    title: 'Enable HTTP Strict-Transport-Security (HSTS)',
    category: 'Cryptographic Failures',
    default_severity: 'Medium',
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    owasp_wstg: 'WSTG-CRYP-01',
    owasp_asvs: 'ASVS V9.1.1',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Return Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses.',
    preventive_measures:
      'Verify SSL/TLS certificate renewal automation and redirect all HTTP traffic to HTTPS.',
    secure_coding_practice:
      'Enforce HSTS at the load balancer or edge proxy tier.',
    code_example:
      'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    priority: 'Medium',
  },
  'HDR-XFO-01': {
    rule_code: 'HDR-XFO-01',
    title: 'Mitigate Clickjacking with X-Frame-Options / frame-ancestors',
    category: 'Security Misconfiguration',
    default_severity: 'Medium',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-CLNT-09',
    owasp_asvs: 'ASVS V14.4.7',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Add X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors \'none\'.',
    preventive_measures:
      'Prevent checkout and login pages from being embedded in external iframes.',
    secure_coding_practice:
      'Apply frame protection across all authenticated and payment views.',
    code_example:
      'X-Frame-Options: DENY',
    priority: 'Medium',
  },
  'HDR-XCTO-01': {
    rule_code: 'HDR-XCTO-01',
    title: 'Set X-Content-Type-Options: nosniff',
    category: 'Security Misconfiguration',
    default_severity: 'Low',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-CONF-07',
    owasp_asvs: 'ASVS V14.4.4',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Configure the web server to emit X-Content-Type-Options: nosniff on every response.',
    preventive_measures:
      'Always declare explicit Content-Type headers alongside nosniff.',
    secure_coding_practice:
      'Prevent browsers from MIME-sniffing user-uploaded product images or files as executable scripts.',
    code_example:
      'X-Content-Type-Options: nosniff',
    priority: 'Low',
  },
  'HDR-REF-01': {
    rule_code: 'HDR-REF-01',
    title: 'Configure Strict Referrer-Policy Header',
    category: 'Security Misconfiguration',
    default_severity: 'Low',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-CONF-07',
    owasp_asvs: 'ASVS V14.4.6',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Emit Referrer-Policy: strict-origin-when-cross-origin on all storefront responses.',
    preventive_measures:
      'Avoid passing order IDs, reset tokens, or PII inside URL query parameters.',
    secure_coding_practice:
      'Combine Referrer-Policy with rel="noopener noreferrer" on outbound links.',
    code_example:
      'Referrer-Policy: strict-origin-when-cross-origin',
    priority: 'Low',
  },
  'HDR-INFO-01': {
    rule_code: 'HDR-INFO-01',
    title: 'Suppress Server & Framework Version Banners',
    category: 'Security Misconfiguration',
    default_severity: 'Low',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-INFO-02',
    owasp_asvs: 'ASVS V14.3.3',
    nist_800_115: 'NIST SP 800-115 §5.1',
    remediation_steps:
      '1. Remove X-Powered-By and strip detailed patch numbers from Server headers.',
    preventive_measures:
      'Harden edge reverse-proxy response header policies.',
    secure_coding_practice:
      'Minimize reconnaissance metadata exposed to automated scanners.',
    code_example:
      'app.disable("x-powered-by");',
    priority: 'Low',
  },
  'TRANS-HTTP-01': {
    rule_code: 'TRANS-HTTP-01',
    title: 'Eliminate Cleartext HTTP Form Actions & Mixed Content',
    category: 'Cryptographic Failures',
    default_severity: 'High',
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    owasp_wstg: 'WSTG-CRYP-03',
    owasp_asvs: 'ASVS V9.1.1',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Update all <form action="..."> URLs and embedded script/asset references to HTTPS.\n2. Enforce upgrade-insecure-requests in CSP.',
    preventive_measures:
      'Block mixed-content builds in CI checks.',
    secure_coding_practice:
      'Use relative paths (e.g. action="/checkout") or strict HTTPS origins.',
    code_example:
      '<form method="POST" action="/checkout"> <!-- Never http:// -->',
    priority: 'High',
  },
  'AUTH-AUTOCOMPLETE-01': {
    rule_code: 'AUTH-AUTOCOMPLETE-01',
    title: 'Disable Browser Caching on Payment Card & CVV Inputs',
    category: 'Identification & Authentication Failures',
    default_severity: 'Low',
    owasp_top10: 'A07:2021 - Identification and Authentication Failures',
    owasp_wstg: 'WSTG-ATHN-06',
    owasp_asvs: 'ASVS V2.1.1',
    nist_800_115: 'NIST SP 800-115 §6.2',
    remediation_steps:
      '1. Set autocomplete="off" on payment card number and CVV inputs.\n2. Use tokenized PCI-DSS compliant payment elements rather than raw card fields.',
    preventive_measures:
      'Delegate card capture to hosted payment fields (iframe isolation).',
    secure_coding_practice:
      'Emit Cache-Control: no-store on checkout and account views.',
    code_example:
      '<input type="password" name="cvv" autocomplete="off" />',
    priority: 'Low',
  },
  'CORS-WILDCARD-01': {
    rule_code: 'CORS-WILDCARD-01',
    title: 'Restrict Overly Permissive CORS Policy',
    category: 'Security Misconfiguration',
    default_severity: 'Medium',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-CLNT-07',
    owasp_asvs: 'ASVS V14.5.3',
    nist_800_115: 'NIST SP 800-115 §5.2',
    remediation_steps:
      '1. Replace wildcard Access-Control-Allow-Origin: * on authenticated routes with an explicit origin allowlist.',
    preventive_measures:
      'Never dynamically reflect untrusted Origin headers without allowlist verification.',
    secure_coding_practice:
      'Scope CORS policies strictly to public read-only catalog endpoints if cross-origin access is needed.',
    code_example:
      'const allowedOrigins = ["https://shop.example.com"];',
    priority: 'Medium',
  },
  'DISC-SENSITIVE-01': {
    rule_code: 'DISC-SENSITIVE-01',
    title: 'Block Public Access to Exposed Configuration Artifacts',
    category: 'Security Misconfiguration',
    default_severity: 'Critical',
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    owasp_wstg: 'WSTG-CONF-04',
    owasp_asvs: 'ASVS V14.3.2',
    nist_800_115: 'NIST SP 800-115 §5.1',
    remediation_steps:
      '1. Remove .env, .git, and backup archives from web-accessible document roots.\n2. Configure web server deny rules for dotfiles.',
    preventive_measures:
      'Deploy compiled build artifacts only, excluding environment and VCS metadata.',
    secure_coding_practice:
      'Store runtime secrets in managed environment variables outside the web root.',
    code_example:
      'location ~ /\\. { deny all; return 404; }',
    priority: 'Immediate',
  },
};

export function getRecommendationForRule(ruleCode: string): RecommendationRule {
  return (
    RECOMMENDATION_LIBRARY[ruleCode] ?? {
      rule_code: ruleCode,
      title: 'Apply Defense-in-Depth Security Hardening',
      category: 'Security Misconfiguration',
      default_severity: 'Medium',
      owasp_top10: 'A05:2021 - Security Misconfiguration',
      owasp_wstg: 'WSTG-CONF-07',
      owasp_asvs: 'ASVS V14.4',
      nist_800_115: 'NIST SP 800-115 §6.2',
      remediation_steps: '1. Review affected endpoint configuration and apply least-privilege validation.',
      preventive_measures: 'Integrate automated security regression checks into CI/CD pipelines.',
      secure_coding_practice: 'Validate all inputs and enforce explicit security headers.',
      code_example: '// Enforce strict validation and secure HTTP headers',
      priority: 'Medium',
    }
  );
}
