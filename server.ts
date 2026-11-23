import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { db, initDatabase, logAuditEvent } from './server/db.ts';
import {
  createRateLimiter,
  createSession,
  getAuthStatus,
  hashPassword,
  requireAuth,
  requireRole,
  revokeSession,
  verifyEnvAdminPasscode,
  verifyPassword,
  type AuthenticatedRequest,
  type UserRole,
} from './server/security/auth.ts';
import { DEMO_STORE_BASE_URL, validateScanTargetUrl } from './server/security/urlValidator.ts';
import { fetchDemoStorePage, getDemoStorePosture, setDemoStorePosture } from './server/scanner/demoStore.ts';
import { startScanJob, stopActiveScan } from './server/scanner/engine.ts';
import { RECOMMENDATION_LIBRARY } from './server/scanner/recommendations.ts';

initDatabase();

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// Global defensive headers for the platform itself
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

const authLimiter = createRateLimiter(20, 60_000);
const scanLimiter = createRateLimiter(15, 60_000);
const apiLimiter = createRateLimiter(180, 60_000);

app.use('/api', apiLimiter);

function sanitizeCsvCell(value: string | number | null | undefined): string {
  const str = value === null || value === undefined ? '' : String(value);
  const neutralized = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
  return `"${neutralized.replaceAll('"', '""')}"`;
}

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'AegisCommerce Security Suite' });
});

// Authentication & First-Run Setup
app.get('/api/auth/status', (_req, res) => {
  res.json(getAuthStatus());
});

app.post('/api/auth/bootstrap', authLimiter, (req, res) => {
  const status = getAuthStatus();
  if (status.hasAdmin) {
    res.status(409).json({ error: 'Initial administrator account has already been claimed. Please sign in.' });
    return;
  }

  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const adminPasscode = typeof req.body?.adminPasscode === 'string' ? req.body.adminPasscode : '';

  if (status.envPasscodeConfigured && !verifyEnvAdminPasscode(adminPasscode)) {
    res.status(403).json({ error: 'Invalid administrator setup passcode.' });
    return;
  }

  if (name.length < 2 || name.length > 80) {
    res.status(400).json({ error: 'Name must be between 2 and 80 characters.' });
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: 'Please provide a valid email address.' });
    return;
  }
  if (password.length < 8 || password.length > 128) {
    res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
    return;
  }

  const existing = db.prepare(`SELECT id FROM Users WHERE email = ?`).get(email);
  if (existing) {
    res.status(409).json({ error: 'An account with this email already exists.' });
    return;
  }

  const passwordHash = hashPassword(password);
  const result = db
    .prepare(`INSERT INTO Users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')`)
    .run(name, email, passwordHash);

  const userId = Number(result.lastInsertRowid);
  const { token, expiresAt } = createSession(userId);
  const user = db
    .prepare(`SELECT id, name, email, role, created_at, last_login_at FROM Users WHERE id = ?`)
    .get(userId);

  logAuditEvent({
    userId,
    userEmail: email,
    action: 'ADMIN_BOOTSTRAP',
    target: email,
    details: 'Initial administrator account claimed',
    ipAddress: req.ip,
  });

  res.status(201).json({ token, expiresAt, user });
});

app.post('/api/auth/register', authLimiter, (req, res) => {
  const status = getAuthStatus();
  if (!status.hasAdmin) {
    res.status(400).json({ error: 'Complete initial administrator setup first.' });
    return;
  }

  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (name.length < 2 || name.length > 80) {
    res.status(400).json({ error: 'Name must be between 2 and 80 characters.' });
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: 'Please provide a valid email address.' });
    return;
  }
  if (password.length < 8 || password.length > 128) {
    res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
    return;
  }

  const existing = db.prepare(`SELECT id FROM Users WHERE email = ?`).get(email);
  if (existing) {
    res.status(409).json({ error: 'An account with this email already exists.' });
    return;
  }

  const passwordHash = hashPassword(password);
  const result = db
    .prepare(`INSERT INTO Users (name, email, password_hash, role) VALUES (?, ?, ?, 'analyst')`)
    .run(name, email, passwordHash);

  const userId = Number(result.lastInsertRowid);
  const { token, expiresAt } = createSession(userId);
  const user = db
    .prepare(`SELECT id, name, email, role, created_at, last_login_at FROM Users WHERE id = ?`)
    .get(userId);

  logAuditEvent({
    userId,
    userEmail: email,
    action: 'USER_REGISTERED',
    target: email,
    details: 'Analyst account registered',
    ipAddress: req.ip,
  });

  res.status(201).json({ token, expiresAt, user });
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const row = db
    .prepare(`SELECT id, name, email, password_hash, role, created_at, last_login_at FROM Users WHERE email = ?`)
    .get(email) as
    | {
        id: number;
        name: string;
        email: string;
        password_hash: string;
        role: UserRole;
        created_at: string;
        last_login_at: string | null;
      }
    | undefined;

  if (!row || !verifyPassword(password, row.password_hash)) {
    logAuditEvent({
      userEmail: email,
      action: 'LOGIN_FAILED',
      target: email,
      details: 'Invalid email or password',
      ipAddress: req.ip,
    });
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }

  const { token, expiresAt } = createSession(row.id);
  logAuditEvent({
    userId: row.id,
    userEmail: row.email,
    action: 'LOGIN_SUCCESS',
    target: row.email,
    ipAddress: req.ip,
  });

  res.json({
    token,
    expiresAt,
    user: {
      id: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      created_at: row.created_at,
      last_login_at: new Date().toISOString(),
    },
  });
});

app.post('/api/auth/logout', requireAuth, (req: AuthenticatedRequest, res) => {
  if (req.sessionTokenHash) {
    revokeSession(req.sessionTokenHash);
  }
  logAuditEvent({
    userId: req.user?.id,
    userEmail: req.user?.email,
    action: 'LOGOUT',
    ipAddress: req.ip,
  });
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({ user: req.user });
});

// Dashboard Overview
app.get('/api/dashboard/overview', requireAuth, (_req, res) => {
  const websitesCount = (db.prepare(`SELECT COUNT(*) as c FROM Websites`).get() as { c: number }).c;

  const latestScansPerSite = db
    .prepare(
      `SELECT sh.*
       FROM Scan_History sh
       INNER JOIN (
         SELECT website_id, MAX(id) as max_id
         FROM Scan_History
         WHERE status = 'completed'
         GROUP BY website_id
       ) latest ON latest.max_id = sh.id`
    )
    .all() as { id: number; security_score: number | null; vulnerabilities_found: number }[];

  const overallScore =
    latestScansPerSite.length > 0
      ? Math.round(
          latestScansPerSite.reduce((sum, s) => sum + (s.security_score ?? 0), 0) / latestScansPerSite.length
        )
      : 0;

  const severityCounts = db
    .prepare(
      `SELECT severity, COUNT(*) as count
       FROM Vulnerabilities
       WHERE remediation_status != 'Resolved'
       GROUP BY severity`
    )
    .all() as { severity: string; count: number }[];

  const totalVulnsAll = (db.prepare(`SELECT COUNT(*) as c FROM Vulnerabilities`).get() as { c: number }).c;

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const row of severityCounts) {
    if (row.severity in counts) {
      counts[row.severity as keyof typeof counts] = row.count;
    }
  }

  const owaspBreakdown = db
    .prepare(
      `SELECT owasp_top10 as category, COUNT(*) as count
       FROM Vulnerabilities
       GROUP BY owasp_top10
       ORDER BY count DESC`
    )
    .all() as { category: string; count: number }[];

  const trendHistory = db
    .prepare(
      `SELECT sh.id, w.name as website_name, sh.started_at, sh.security_score, sh.vulnerabilities_found,
              COALESCE(ra.critical_count, 0) as critical_count,
              COALESCE(ra.high_count, 0) as high_count,
              COALESCE(ra.medium_count, 0) as medium_count,
              COALESCE(ra.low_count, 0) as low_count
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       LEFT JOIN Risk_Assessments ra ON ra.scan_id = sh.id
       WHERE sh.status = 'completed'
       ORDER BY sh.id ASC
       LIMIT 15`
    )
    .all();

  const recentScans = db
    .prepare(
      `SELECT sh.*, w.name as website_name, w.base_url, w.domain, w.is_demo_target,
              ra.risk_rating, ra.critical_count, ra.high_count, ra.medium_count, ra.low_count
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       LEFT JOIN Risk_Assessments ra ON ra.scan_id = sh.id
       ORDER BY sh.id DESC
       LIMIT 12`
    )
    .all();

  res.json({
    metrics: {
      totalWebsitesScanned: websitesCount,
      totalVulnerabilitiesDetected: totalVulnsAll,
      activeVulnerabilities: counts.Critical + counts.High + counts.Medium + counts.Low,
      criticalCount: counts.Critical,
      highCount: counts.High,
      mediumCount: counts.Medium,
      lowCount: counts.Low,
      overallSecurityScore: overallScore,
    },
    owaspBreakdown,
    trendHistory,
    recentScans,
  });
});

// Websites list
app.get('/api/websites', requireAuth, (_req, res) => {
  const rows = db
    .prepare(
      `SELECT w.*,
              (SELECT COUNT(*) FROM Scan_History sh WHERE sh.website_id = w.id) as total_scans,
              (SELECT sh.security_score FROM Scan_History sh WHERE sh.website_id = w.id AND sh.status = 'completed' ORDER BY sh.id DESC LIMIT 1) as latest_score,
              (SELECT sh.id FROM Scan_History sh WHERE sh.website_id = w.id AND sh.status = 'completed' ORDER BY sh.id DESC LIMIT 1) as latest_scan_id,
              (SELECT sh.completed_at FROM Scan_History sh WHERE sh.website_id = w.id AND sh.status = 'completed' ORDER BY sh.id DESC LIMIT 1) as last_scanned_at
       FROM Websites w
       ORDER BY w.is_demo_target DESC, w.id DESC`
    )
    .all();
  res.json({ websites: rows });
});

// Demo Store inspection & posture toggle
app.get('/api/demo-store', requireAuth, (_req, res) => {
  const posture = getDemoStorePosture();
  const samplePages = ['/', '/products', '/product?id=101', '/search?q=watch', '/cart', '/checkout', '/login'].map(
    (p) => {
      const resp = fetchDemoStorePage(`${DEMO_STORE_BASE_URL}${p}`);
      return {
        path: p,
        url: resp.finalUrl,
        status: resp.status,
        headers: resp.headers,
        setCookies: resp.setCookies,
        htmlPreview: resp.body,
      };
    }
  );
  res.json({
    url: DEMO_STORE_BASE_URL,
    name: 'Meridian Mart (Demo Store)',
    posture,
    pages: samplePages,
  });
});

app.post('/api/demo-store/posture', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const posture = req.body?.posture === 'hardened' ? 'hardened' : 'vulnerable';
  setDemoStorePosture(posture);
  logAuditEvent({
    userId: req.user?.id,
    userEmail: req.user?.email,
    action: 'DEMO_STORE_POSTURE_CHANGED',
    target: DEMO_STORE_BASE_URL,
    details: `Posture switched to ${posture}`,
    ipAddress: req.ip,
  });
  res.json({ posture });
});

// Start a scan
app.post('/api/scans/start', requireAuth, requireRole(['admin', 'analyst']), scanLimiter, async (req: AuthenticatedRequest, res) => {
  const targetUrlRaw = typeof req.body?.url === 'string' ? req.body.url : '';
  const authorizationConfirmed = req.body?.authorizationConfirmed === true;
  const siteNameRaw = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const scanModeRaw = req.body?.scanMode;
  const scanMode: 'quick' | 'standard' | 'comprehensive' =
    scanModeRaw === 'quick' || scanModeRaw === 'comprehensive' ? scanModeRaw : 'standard';

  const maxPagesNum = Number.parseInt(String(req.body?.maxPages ?? 10), 10);
  const maxPages = Number.isNaN(maxPagesNum) ? 10 : Math.max(1, Math.min(25, maxPagesNum));

  if (!authorizationConfirmed) {
    res.status(400).json({
      error: 'Explicit authorization confirmation is required before initiating any security scan.',
    });
    return;
  }

  let validated;
  try {
    validated = await validateScanTargetUrl(targetUrlRaw);
  } catch (err) {
    res.status(400).json({
      error: err instanceof Error ? err.message : 'Invalid or restricted target URL.',
    });
    return;
  }

  const normalizedOriginUrl = new URL(validated.normalizedUrl);
  const baseUrl = normalizedOriginUrl.origin;
  const siteName =
    siteNameRaw ||
    (validated.isDemoTarget ? 'Meridian Mart (Demo Store)' : normalizedOriginUrl.hostname);

  const existingSite = db.prepare(`SELECT id FROM Websites WHERE base_url = ?`).get(baseUrl) as
    | { id: number }
    | undefined;

  let websiteId: number;
  if (existingSite) {
    websiteId = existingSite.id;
    db.prepare(`UPDATE Websites SET authorization_confirmed = 1 WHERE id = ?`).run(websiteId);
  } else {
    const insertSite = db
      .prepare(
        `INSERT INTO Websites (user_id, name, base_url, domain, authorization_confirmed, is_demo_target)
         VALUES (?, ?, ?, ?, 1, ?)`
      )
      .run(
        req.user!.id,
        siteName,
        baseUrl,
        validated.hostname,
        validated.isDemoTarget ? 1 : 0
      );
    websiteId = Number(insertSite.lastInsertRowid);
  }

  const scanId = startScanJob({
    websiteId,
    userId: req.user!.id,
    userEmail: req.user!.email,
    targetUrl: validated.normalizedUrl,
    isDemoTarget: validated.isDemoTarget,
    scanMode,
    maxPages,
    checkSqli: req.body?.checkSqli !== false,
    checkXss: req.body?.checkXss !== false,
    checkHeaders: req.body?.checkHeaders !== false,
    checkCookies: req.body?.checkCookies !== false,
    checkMisconfig: req.body?.checkMisconfig !== false,
  });

  res.status(201).json({ scanId, websiteId, targetUrl: validated.normalizedUrl });
});

app.post('/api/scans/:id/stop', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const scanId = Number.parseInt(String(req.params.id), 10);
  if (Number.isNaN(scanId)) {
    res.status(400).json({ error: 'Invalid scan ID.' });
    return;
  }
  const stopped = stopActiveScan(scanId);
  if (!stopped) {
    db.prepare(
      `UPDATE Scan_History SET status = 'stopped', completed_at = datetime('now'), current_url = '' WHERE id = ? AND status IN ('queued', 'running')`
    ).run(scanId);
  }
  logAuditEvent({
    userId: req.user?.id,
    userEmail: req.user?.email,
    action: 'SCAN_STOPPED',
    target: `Scan #${scanId}`,
    ipAddress: req.ip,
  });
  res.json({ ok: true, scanId });
});

app.post('/api/scans/:id/rescan', requireAuth, requireRole(['admin', 'analyst']), scanLimiter, async (req: AuthenticatedRequest, res) => {
  const prevScanId = Number.parseInt(String(req.params.id), 10);
  if (Number.isNaN(prevScanId)) {
    res.status(400).json({ error: 'Invalid scan ID.' });
    return;
  }

  const prev = db
    .prepare(
      `SELECT sh.*, w.base_url, w.is_demo_target, w.authorization_confirmed
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       WHERE sh.id = ?`
    )
    .get(prevScanId) as
    | {
        website_id: number;
        base_url: string;
        is_demo_target: number;
        authorization_confirmed: number;
        scan_mode: 'quick' | 'standard' | 'comprehensive';
        max_pages: number;
        check_sqli: number;
        check_xss: number;
        check_headers: number;
        check_cookies: number;
        check_misconfig: number;
      }
    | undefined;

  if (!prev) {
    res.status(404).json({ error: 'Previous scan not found.' });
    return;
  }

  if (!prev.authorization_confirmed && !prev.is_demo_target) {
    res.status(400).json({
      error: 'Sample dataset websites cannot be scanned externally without explicit authorization. Start a new authorized scan or scan the Demo Store.',
    });
    return;
  }

  try {
    await validateScanTargetUrl(prev.base_url);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid target URL for rescan.' });
    return;
  }

  const newScanId = startScanJob({
    websiteId: prev.website_id,
    userId: req.user!.id,
    userEmail: req.user!.email,
    targetUrl: `${prev.base_url}/`,
    isDemoTarget: prev.is_demo_target === 1,
    scanMode: prev.scan_mode,
    maxPages: prev.max_pages,
    checkSqli: prev.check_sqli === 1,
    checkXss: prev.check_xss === 1,
    checkHeaders: prev.check_headers === 1,
    checkCookies: prev.check_cookies === 1,
    checkMisconfig: prev.check_misconfig === 1,
  });

  res.status(201).json({ scanId: newScanId });
});

app.get('/api/scans', requireAuth, (_req, res) => {
  const scans = db
    .prepare(
      `SELECT sh.*, w.name as website_name, w.base_url, w.domain, w.is_demo_target,
              ra.risk_rating, ra.critical_count, ra.high_count, ra.medium_count, ra.low_count, ra.false_positives_filtered
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       LEFT JOIN Risk_Assessments ra ON ra.scan_id = sh.id
       ORDER BY sh.id DESC`
    )
    .all();
  res.json({ scans });
});

app.get('/api/scans/:id', requireAuth, (req, res) => {
  const scanId = Number.parseInt(String(req.params.id), 10);
  if (Number.isNaN(scanId)) {
    res.status(400).json({ error: 'Invalid scan ID.' });
    return;
  }

  const scan = db
    .prepare(
      `SELECT sh.*, w.name as website_name, w.base_url, w.domain, w.is_demo_target
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       WHERE sh.id = ?`
    )
    .get(scanId);

  if (!scan) {
    res.status(404).json({ error: 'Scan record not found.' });
    return;
  }

  const pages = db
    .prepare(`SELECT * FROM Scanned_Pages WHERE scan_id = ? ORDER BY id ASC`)
    .all(scanId);

  const riskAssessment = db
    .prepare(`SELECT * FROM Risk_Assessments WHERE scan_id = ?`)
    .get(scanId) ?? null;

  const vulnerabilities = db
    .prepare(
      `SELECT v.*, sr.title as rec_title, sr.remediation_steps, sr.preventive_measures,
              sr.secure_coding_practice, sr.code_example, sr.priority as rec_priority
       FROM Vulnerabilities v
       LEFT JOIN Security_Recommendations sr ON sr.vulnerability_id = v.id
       WHERE v.scan_id = ?
       ORDER BY CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, v.id ASC`
    )
    .all(scanId);

  res.json({ scan, pages, riskAssessment, vulnerabilities });
});

// Vulnerabilities Explorer & Status Management
app.get('/api/vulnerabilities', requireAuth, (req, res) => {
  const severity = typeof req.query.severity === 'string' ? req.query.severity : '';
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const category = typeof req.query.category === 'string' ? req.query.category : '';
  const scanId = typeof req.query.scanId === 'string' ? Number.parseInt(req.query.scanId, 10) : NaN;
  const search = typeof req.query.q === 'string' ? req.query.q.trim() : '';

  const whereClauses: string[] = [];
  const params: (string | number)[] = [];

  if (severity && severity !== 'All') {
    whereClauses.push('v.severity = ?');
    params.push(severity);
  }
  if (status && status !== 'All') {
    whereClauses.push('v.remediation_status = ?');
    params.push(status);
  }
  if (category && category !== 'All') {
    whereClauses.push('v.category = ?');
    params.push(category);
  }
  if (!Number.isNaN(scanId)) {
    whereClauses.push('v.scan_id = ?');
    params.push(scanId);
  }
  if (search) {
    whereClauses.push('(v.name LIKE ? OR v.affected_url LIKE ? OR v.owasp_top10 LIKE ? OR v.rule_code LIKE ?)');
    const like = `%${search}%`;
    params.push(like, like, like, like);
  }

  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  const vulnerabilities = db
    .prepare(
      `SELECT v.*, w.name as website_name, w.base_url,
              sr.title as rec_title, sr.remediation_steps, sr.preventive_measures,
              sr.secure_coding_practice, sr.code_example, sr.priority as rec_priority
       FROM Vulnerabilities v
       JOIN Websites w ON w.id = v.website_id
       LEFT JOIN Security_Recommendations sr ON sr.vulnerability_id = v.id
       ${whereSql}
       ORDER BY CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, v.id DESC
       LIMIT 300`
    )
    .all(...params);

  res.json({ vulnerabilities });
});

app.patch(
  '/api/vulnerabilities/:id/status',
  requireAuth,
  requireRole(['admin', 'analyst']),
  (req: AuthenticatedRequest, res) => {
    const vulnId = Number.parseInt(String(req.params.id), 10);
    const nextStatus = req.body?.status;
    const allowed = ['Open', 'In Progress', 'Resolved', 'Accepted Risk'];

    if (Number.isNaN(vulnId) || !allowed.includes(nextStatus)) {
      res.status(400).json({ error: 'Invalid vulnerability ID or remediation status.' });
      return;
    }

    const existing = db.prepare(`SELECT id, name FROM Vulnerabilities WHERE id = ?`).get(vulnId) as
      | { id: number; name: string }
      | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Vulnerability not found.' });
      return;
    }

    db.prepare(`UPDATE Vulnerabilities SET remediation_status = ? WHERE id = ?`).run(nextStatus, vulnId);
    logAuditEvent({
      userId: req.user?.id,
      userEmail: req.user?.email,
      action: 'VULNERABILITY_STATUS_UPDATED',
      target: `Vulnerability #${vulnId} (${existing.name})`,
      details: `Remediation status set to ${nextStatus}`,
      ipAddress: req.ip,
    });

    res.json({ ok: true, id: vulnId, status: nextStatus });
  }
);

// Comparison between two scans
app.get('/api/comparison', requireAuth, (req, res) => {
  const scanAId = Number.parseInt(String(req.query.scanA ?? ''), 10);
  const scanBId = Number.parseInt(String(req.query.scanB ?? ''), 10);

  if (Number.isNaN(scanAId) || Number.isNaN(scanBId)) {
    res.status(400).json({ error: 'Both scanA and scanB IDs are required.' });
    return;
  }

  const fetchSummary = (id: number) =>
    db
      .prepare(
        `SELECT sh.*, w.name as website_name, w.base_url,
                ra.overall_score, ra.risk_rating, ra.critical_count, ra.high_count,
                ra.medium_count, ra.low_count, ra.false_positives_filtered
         FROM Scan_History sh
         JOIN Websites w ON w.id = sh.website_id
         LEFT JOIN Risk_Assessments ra ON ra.scan_id = sh.id
         WHERE sh.id = ?`
      )
      .get(id);

  const scanA = fetchSummary(scanAId);
  const scanB = fetchSummary(scanBId);
  if (!scanA || !scanB) {
    res.status(404).json({ error: 'One or both scans were not found.' });
    return;
  }

  const vulnsA = db.prepare(`SELECT rule_code, name, severity, affected_url FROM Vulnerabilities WHERE scan_id = ?`).all(scanAId) as {
    rule_code: string;
    name: string;
    severity: string;
    affected_url: string;
  }[];
  const vulnsB = db.prepare(`SELECT rule_code, name, severity, affected_url FROM Vulnerabilities WHERE scan_id = ?`).all(scanBId) as {
    rule_code: string;
    name: string;
    severity: string;
    affected_url: string;
  }[];

  const rulesB = new Set(vulnsB.map((v) => v.rule_code));
  const rulesA = new Set(vulnsA.map((v) => v.rule_code));

  const resolvedFindings = vulnsA.filter((v) => !rulesB.has(v.rule_code));
  const newFindings = vulnsB.filter((v) => !rulesA.has(v.rule_code));
  const persistentFindings = vulnsB.filter((v) => rulesA.has(v.rule_code));

  res.json({ scanA, scanB, resolvedFindings, newFindings, persistentFindings });
});

// Recommendations Knowledge Library
app.get('/api/recommendations', requireAuth, (_req, res) => {
  res.json({ recommendations: Object.values(RECOMMENDATION_LIBRARY) });
});

// Reports Archive & Generation
app.get('/api/reports', requireAuth, (_req, res) => {
  const reports = db
    .prepare(
      `SELECT gr.*, w.name as website_name, w.base_url, u.name as generated_by_name
       FROM Generated_Reports gr
       JOIN Websites w ON w.id = gr.website_id
       LEFT JOIN Users u ON u.id = gr.user_id
       ORDER BY gr.id DESC`
    )
    .all();
  res.json({ reports });
});

app.post('/api/reports', requireAuth, (req: AuthenticatedRequest, res) => {
  const scanId = Number.parseInt(String(req.body?.scanId ?? ''), 10);
  const format = req.body?.format === 'CSV' ? 'CSV' : 'PDF';

  if (Number.isNaN(scanId)) {
    res.status(400).json({ error: 'Valid scanId is required.' });
    return;
  }

  const scan = db
    .prepare(
      `SELECT sh.*, w.name as website_name, w.base_url, w.domain
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       WHERE sh.id = ?`
    )
    .get(scanId) as
    | {
        id: number;
        website_id: number;
        website_name: string;
        base_url: string;
        domain: string;
        pages_scanned: number;
        vulnerabilities_found: number;
        security_score: number | null;
        started_at: string;
        completed_at: string | null;
      }
    | undefined;

  if (!scan) {
    res.status(404).json({ error: 'Scan not found.' });
    return;
  }

  const riskAssessment = db.prepare(`SELECT * FROM Risk_Assessments WHERE scan_id = ?`).get(scanId);
  const vulnerabilities = db
    .prepare(
      `SELECT v.*, sr.title as rec_title, sr.remediation_steps, sr.preventive_measures,
              sr.secure_coding_practice, sr.code_example
       FROM Vulnerabilities v
       LEFT JOIN Security_Recommendations sr ON sr.vulnerability_id = v.id
       WHERE v.scan_id = ?
       ORDER BY CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END`
    )
    .all(scanId);

  const reportTitle = `${scan.website_name} — Security Assessment (#${scan.id})`;
  const insert = db
    .prepare(
      `INSERT INTO Generated_Reports (scan_id, website_id, user_id, report_title, format, vulnerability_count, security_score)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      scan.id,
      scan.website_id,
      req.user!.id,
      reportTitle,
      format,
      vulnerabilities.length,
      scan.security_score ?? 0
    );

  logAuditEvent({
    userId: req.user?.id,
    userEmail: req.user?.email,
    action: 'REPORT_GENERATED',
    target: reportTitle,
    details: `Format: ${format}`,
    ipAddress: req.ip,
  });

  res.status(201).json({
    reportId: Number(insert.lastInsertRowid),
    reportTitle,
    scan,
    riskAssessment,
    vulnerabilities,
  });
});

app.get('/api/scans/:id/export/csv', requireAuth, (req: AuthenticatedRequest, res) => {
  const scanId = Number.parseInt(String(req.params.id), 10);
  if (Number.isNaN(scanId)) {
    res.status(400).json({ error: 'Invalid scan ID.' });
    return;
  }

  const scan = db
    .prepare(
      `SELECT sh.id, sh.website_id, sh.security_score, w.name as website_name, w.base_url
       FROM Scan_History sh
       JOIN Websites w ON w.id = sh.website_id
       WHERE sh.id = ?`
    )
    .get(scanId) as
    | { id: number; website_id: number; security_score: number | null; website_name: string; base_url: string }
    | undefined;

  if (!scan) {
    res.status(404).json({ error: 'Scan not found.' });
    return;
  }

  const rows = db
    .prepare(
      `SELECT v.*, sr.title as rec_title, sr.remediation_steps
       FROM Vulnerabilities v
       LEFT JOIN Security_Recommendations sr ON sr.vulnerability_id = v.id
       WHERE v.scan_id = ?
       ORDER BY CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END`
    )
    .all(scanId) as Record<string, string | number | null>[];

  db.prepare(
    `INSERT INTO Generated_Reports (scan_id, website_id, user_id, report_title, format, vulnerability_count, security_score)
     VALUES (?, ?, ?, ?, 'CSV', ?, ?)`
  ).run(
    scan.id,
    scan.website_id,
    req.user!.id,
    `${scan.website_name} — CSV Vulnerability Export (#${scan.id})`,
    rows.length,
    scan.security_score ?? 0
  );

  logAuditEvent({
    userId: req.user?.id,
    userEmail: req.user?.email,
    action: 'CSV_EXPORTED',
    target: `Scan #${scan.id}`,
    ipAddress: req.ip,
  });

  const headers = [
    'ID',
    'Rule Code',
    'Vulnerability Name',
    'Category',
    'Severity',
    'Confidence',
    'Status',
    'Affected URL',
    'Parameter',
    'OWASP Top 10',
    'OWASP WSTG',
    'OWASP ASVS',
    'NIST SP 800-115',
    'Evidence',
    'Recommended Solution',
  ];

  const lines = [headers.map(sanitizeCsvCell).join(',')];
  for (const r of rows) {
    lines.push(
      [
        r.id,
        r.rule_code,
        r.name,
        r.category,
        r.severity,
        r.confidence,
        r.remediation_status,
        r.affected_url,
        r.parameter_name,
        r.owasp_top10,
        r.owasp_wstg,
        r.owasp_asvs,
        r.nist_800_115,
        r.evidence,
        r.remediation_steps ?? r.rec_title ?? '',
      ]
        .map(sanitizeCsvCell)
        .join(',')
    );
  }

  const safeSlug = scan.website_name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="aegis-${safeSlug}-scan-${scan.id}.csv"`);
  res.send(lines.join('\r\n'));
});

// Admin RBAC & Audit Logs
app.get('/api/admin/users', requireAuth, requireRole(['admin']), (_req, res) => {
  const users = db
    .prepare(`SELECT id, name, email, role, created_at, last_login_at FROM Users ORDER BY id ASC`)
    .all();
  res.json({ users });
});

app.patch('/api/admin/users/:id/role', requireAuth, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const targetUserId = Number.parseInt(String(req.params.id), 10);
  const newRole = req.body?.role;
  if (Number.isNaN(targetUserId) || !['admin', 'analyst', 'viewer'].includes(newRole)) {
    res.status(400).json({ error: 'Invalid user ID or role.' });
    return;
  }

  if (targetUserId === req.user!.id && newRole !== 'admin') {
    const adminCount = (db.prepare(`SELECT COUNT(*) as c FROM Users WHERE role = 'admin'`).get() as { c: number }).c;
    if (adminCount <= 1) {
      res.status(400).json({ error: 'Cannot remove admin role from the sole remaining administrator.' });
      return;
    }
  }

  const target = db.prepare(`SELECT email FROM Users WHERE id = ?`).get(targetUserId) as { email: string } | undefined;
  if (!target) {
    res.status(404).json({ error: 'User not found.' });
    return;
  }

  db.prepare(`UPDATE Users SET role = ? WHERE id = ?`).run(newRole, targetUserId);
  logAuditEvent({
    userId: req.user?.id,
    userEmail: req.user?.email,
    action: 'USER_ROLE_UPDATED',
    target: target.email,
    details: `Role changed to ${newRole}`,
    ipAddress: req.ip,
  });

  res.json({ ok: true });
});

app.get('/api/admin/audit-logs', requireAuth, requireRole(['admin']), (_req, res) => {
  const logs = db.prepare(`SELECT * FROM Audit_Logs ORDER BY id DESC LIMIT 150`).all();
  res.json({ logs });
});

// Vite dev middleware or production static build
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      const indexHtml = path.join(distDir, 'index.html');
      if (fs.existsSync(indexHtml)) {
        res.sendFile(indexHtml);
      } else {
        res.status(404).send('Build output not found. Run npm run build.');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AegisCommerce Security Suite listening on http://0.0.0.0:${PORT}`);
  });
}

void startServer();
