import { useState, type FormEvent } from 'react';
import { Lock, ShieldCheck, UserPlus } from 'lucide-react';
import { apiFetch, setAuthToken } from '../lib/api';
import type { AuthStatus, UserProfile } from '../types';

interface AuthGateProps {
  authStatus: AuthStatus;
  onAuthenticated: (user: UserProfile) => void;
}

export function AuthGate({ authStatus, onAuthenticated }: AuthGateProps) {
  const needsBootstrap = !authStatus.hasAdmin;
  const [mode, setMode] = useState<'bootstrap' | 'login' | 'register'>(
    needsBootstrap ? 'bootstrap' : 'login'
  );
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [adminPasscode, setAdminPasscode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const endpoint =
        mode === 'bootstrap'
          ? '/api/auth/bootstrap'
          : mode === 'register'
            ? '/api/auth/register'
            : '/api/auth/login';

      const payload =
        mode === 'login'
          ? { email, password }
          : mode === 'bootstrap'
            ? { name, email, password, adminPasscode }
            : { name, email, password };

      const res = await apiFetch<{ token: string; user: UserProfile }>(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      setAuthToken(res.token);
      onAuthenticated(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex items-center justify-center p-6">
      <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 border border-slate-800/90 bg-[#0D1424] rounded-xl overflow-hidden">
        {/* Left Context Panel */}
        <div className="lg:col-span-6 p-8 lg:p-10 flex flex-col justify-between bg-[#090F1D] border-b lg:border-b-0 lg:border-r border-slate-800/80">
          <div>
            <div className="flex items-center gap-2.5 text-cyan-400 mb-6">
              <ShieldCheck className="w-6 h-6 shrink-0" aria-hidden="true" />
              <span className="font-display text-lg font-semibold tracking-tight text-white">
                AegisCommerce
              </span>
            </div>
            <h1 className="font-display text-2xl lg:text-3xl font-semibold text-white leading-tight mb-4">
              Automated E-Commerce Vulnerability Detection & Security Assessment
            </h1>
            <p className="text-sm text-slate-400 leading-relaxed mb-8">
              Authorized, non-destructive security testing mapped to OWASP Top 10, WSTG, ASVS v4.0, and NIST SP 800-115. Evaluate checkout flows, session cookies, security headers, and remediation progress from a unified workspace.
            </p>
          </div>

          <div className="space-y-4 pt-6 border-t border-slate-800/80 text-xs text-slate-400">
            <div className="flex items-start gap-3">
              <span className="text-cyan-400 font-mono tabular-nums mt-0.5">01</span>
              <div>
                <p className="text-slate-200 font-medium">Non-Destructive Verification</p>
                <p>Strictly blocks private networks, loopback addresses, and cloud metadata endpoints.</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-cyan-400 font-mono tabular-nums mt-0.5">02</span>
              <div>
                <p className="text-slate-200 font-medium">Sandboxed Demo Target Included</p>
                <p>Evaluate detection, risk scoring, patching, and rescanning immediately on Meridian Mart.</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-cyan-400 font-mono tabular-nums mt-0.5">03</span>
              <div>
                <p className="text-slate-200 font-medium">Audit & Export Ready</p>
                <p>Generate formatted PDF security assessments and sanitized CSV exports.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Form Panel */}
        <div className="lg:col-span-6 p-8 lg:p-10 flex flex-col justify-center">
          <div className="mb-6">
            <h2 className="font-display text-xl font-semibold text-white">
              {mode === 'bootstrap'
                ? 'Initial Administrator Setup'
                : mode === 'register'
                  ? 'Create Analyst Account'
                  : 'Sign In to Workspace'}
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              {mode === 'bootstrap'
                ? 'Claim the initial administrator account to unlock authorized scanning and reporting.'
                : mode === 'register'
                  ? 'Register an analyst profile with scanning and remediation permissions.'
                  : 'Enter your credentials to access scan results, vulnerability details, and reports.'}
            </p>
          </div>

          {!needsBootstrap && (
            <div className="flex items-center gap-1 p-1 bg-[#070B14] border border-slate-800 rounded-lg mb-6">
              <button
                type="button"
                onClick={() => {
                  setMode('login');
                  setError('');
                }}
                className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  mode === 'login'
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('register');
                  setError('');
                }}
                className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  mode === 'register'
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Create Account
              </button>
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mb-5 p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {(mode === 'bootstrap' || mode === 'register') && (
              <div>
                <label htmlFor="auth-name" className="block text-xs font-medium text-slate-300 mb-1.5">
                  Full Name
                </label>
                <input
                  id="auth-name"
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Dr. Alex Morgan"
                  className="w-full px-3.5 py-2.5 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            )}

            <div>
              <label htmlFor="auth-email" className="block text-xs font-medium text-slate-300 mb-1.5">
                Email Address
              </label>
              <input
                id="auth-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@organization.edu"
                className="w-full px-3.5 py-2.5 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-xs font-medium text-slate-300 mb-1.5">
                Password {mode !== 'login' && <span className="text-slate-500">(minimum 8 characters)</span>}
              </label>
              <input
                id="auth-password"
                type="password"
                required
                minLength={mode === 'login' ? 1 : 8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {mode === 'bootstrap' && authStatus.envPasscodeConfigured && (
              <div>
                <label htmlFor="auth-passcode" className="block text-xs font-medium text-slate-300 mb-1.5">
                  Administrator Setup Passcode
                </label>
                <input
                  id="auth-passcode"
                  type="password"
                  required
                  value={adminPasscode}
                  onChange={(e) => setAdminPasscode(e.target.value)}
                  placeholder="Configured ADMIN_PASSCODE"
                  className="w-full px-3.5 py-2.5 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer"
            >
              {mode === 'bootstrap' ? (
                <>
                  <Lock className="w-4 h-4" aria-hidden="true" />
                  {loading ? 'Creating Administrator...' : 'Claim Administrator Account'}
                </>
              ) : mode === 'register' ? (
                <>
                  <UserPlus className="w-4 h-4" aria-hidden="true" />
                  {loading ? 'Creating Account...' : 'Register Analyst Account'}
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" aria-hidden="true" />
                  {loading ? 'Signing In...' : 'Sign In'}
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
