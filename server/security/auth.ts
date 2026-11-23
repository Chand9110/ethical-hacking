import crypto from 'crypto';
import type { NextFunction, Request, Response } from 'express';
import { db } from '../db.ts';

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface AuthenticatedUser {
  id: number;
  name: string;
  email: string;
  role: UserRole;
  created_at: string;
  last_login_at: string | null;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
  sessionTokenHash?: string;
}

const SESSION_DURATION_HOURS = 24;

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  const derivedBuf = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (derivedBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derivedBuf, expectedBuf);
}

export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function createSession(userId: number): { token: string; expiresAt: string } {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashSessionToken(token);
  const expiresAtDate = new Date(Date.now() + SESSION_DURATION_HOURS * 60 * 60 * 1000);
  const expiresAt = expiresAtDate.toISOString();

  db.prepare(`DELETE FROM Sessions WHERE expires_at < datetime('now')`).run();
  db.prepare(`INSERT INTO Sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`).run(
    tokenHash,
    userId,
    expiresAt
  );
  db.prepare(`UPDATE Users SET last_login_at = datetime('now') WHERE id = ?`).run(userId);

  return { token, expiresAt };
}

export function revokeSession(tokenHash: string): void {
  db.prepare(`DELETE FROM Sessions WHERE token_hash = ?`).run(tokenHash);
}

export function getAuthStatus(): {
  hasUsers: boolean;
  hasAdmin: boolean;
  envPasscodeConfigured: boolean;
} {
  const userCount = (db.prepare(`SELECT COUNT(*) as c FROM Users`).get() as { c: number }).c;
  const adminCount = (db.prepare(`SELECT COUNT(*) as c FROM Users WHERE role = 'admin'`).get() as { c: number }).c;
  const envPasscodeConfigured = Boolean(process.env.ADMIN_PASSCODE && process.env.ADMIN_PASSCODE.trim().length > 0);
  return {
    hasUsers: userCount > 0,
    hasAdmin: adminCount > 0,
    envPasscodeConfigured,
  };
}

export function verifyEnvAdminPasscode(inputPasscode: string): boolean {
  const configured = process.env.ADMIN_PASSCODE?.trim();
  if (!configured) return false;
  const inputBuf = Buffer.from(inputPasscode);
  const configuredBuf = Buffer.from(configured);
  if (inputBuf.length !== configuredBuf.length) return false;
  return crypto.timingSafeEqual(inputBuf, configuredBuf);
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
    return;
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    res.status(401).json({ error: 'Invalid authorization token.' });
    return;
  }

  const tokenHash = hashSessionToken(token);
  const row = db
    .prepare(
      `SELECT u.id, u.name, u.email, u.role, u.created_at, u.last_login_at, s.expires_at
       FROM Sessions s
       JOIN Users u ON u.id = s.user_id
       WHERE s.token_hash = ?`
    )
    .get(tokenHash) as (AuthenticatedUser & { expires_at: string }) | undefined;

  if (!row) {
    res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
    return;
  }

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    revokeSession(tokenHash);
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
    return;
  }

  req.user = {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    created_at: row.created_at,
    last_login_at: row.last_login_at,
  };
  req.sessionTokenHash = tokenHash;
  next();
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: `Insufficient permissions. Requires role: ${allowedRoles.join(' or ')}.` });
      return;
    }
    next();
  };
}

interface RateBucket {
  count: number;
  resetAt: number;
}

export function createRateLimiter(maxRequests: number, windowMs: number) {
  const buckets = new Map<string, RateBucket>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = `${req.ip || 'unknown'}:${req.baseUrl}${req.path}`;
    const now = Date.now();
    const current = buckets.get(key);

    if (!current || now >= current.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }

    if (current.count >= maxRequests) {
      const retryAfterSec = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.status(429).json({
        error: `Rate limit exceeded. Please wait ${retryAfterSec} seconds before retrying.`,
      });
      return;
    }

    current.count += 1;
    next();
  };
}
