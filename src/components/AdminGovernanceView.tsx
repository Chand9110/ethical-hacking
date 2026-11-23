import { useEffect, useState } from 'react';
import { Shield, UserCog } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AuditLogRecord, UserProfile, UserRole } from '../types';

export function AdminGovernanceView({ currentUserId }: { currentUserId: number }) {
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadAdminData = async () => {
    setLoading(true);
    setError('');
    try {
      const [usersRes, logsRes] = await Promise.all([
        apiFetch<{ users: UserProfile[] }>('/api/admin/users'),
        apiFetch<{ logs: AuditLogRecord[] }>('/api/admin/audit-logs'),
      ]);
      setUsers(usersRes.users);
      setLogs(logsRes.logs);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load governance records.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadAdminData();
  }, []);

  const handleRoleChange = async (userId: number, role: UserRole) => {
    setError('');
    try {
      await apiFetch(`/api/admin/users/${userId}/role`, {
        method: 'PATCH',
        body: JSON.stringify({ role }),
      });
      await loadAdminData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to update user role.');
    }
  };

  if (loading) {
    return <div className="h-72 rounded-xl bg-[#0D1424] border border-slate-800/80 animate-pulse" />;
  }

  return (
    <div className="space-y-6">
      {error && (
        <div role="alert" className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* RBAC Users Table */}
      <div className="rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex items-center gap-2.5">
          <UserCog className="w-4 h-4 text-cyan-400" aria-hidden="true" />
          <div>
            <h3 className="font-display text-base font-semibold text-white">Role-Based Access Control</h3>
            <p className="text-xs text-slate-400">Manage user permissions across scanning, remediation, and administration</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800/80 text-[11px] font-medium text-slate-400 bg-[#090F1D]">
                <th className="py-3 px-4">Name</th>
                <th className="py-3 px-4">Email</th>
                <th className="py-3 px-4">Last Login</th>
                <th className="py-3 px-4 text-right">Assigned Role</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-800/25">
                  <td className="py-3 px-4 font-medium text-slate-100">
                    {u.name} {u.id === currentUserId ? '(You)' : ''}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300">{u.email}</td>
                  <td className="py-3 px-4 font-mono tabular-nums text-slate-400">
                    {u.last_login_at ? u.last_login_at.slice(0, 19).replace('T', ' ') : '—'}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <select
                      aria-label={`Role for ${u.email}`}
                      value={u.role}
                      onChange={(e) => void handleRoleChange(u.id, e.target.value as UserRole)}
                      className="px-2.5 py-1 text-xs bg-[#070B14] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="admin">Admin</option>
                      <option value="analyst">Analyst</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Logs */}
      <div className="rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex items-center gap-2.5">
          <Shield className="w-4 h-4 text-cyan-400" aria-hidden="true" />
          <div>
            <h3 className="font-display text-base font-semibold text-white">Security Audit Logs</h3>
            <p className="text-xs text-slate-400">Immutable record of authentication events, scans, status updates, and exports</p>
          </div>
        </div>
        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800/80 text-[11px] font-medium text-slate-400 bg-[#090F1D]">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/25">
                  <td className="py-2.5 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                    {log.created_at.slice(0, 19)}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-slate-300">{log.user_email || 'System'}</td>
                  <td className="py-2.5 px-4 font-mono text-cyan-300">{log.action}</td>
                  <td className="py-2.5 px-4 font-mono text-slate-300 max-w-[200px] truncate">
                    {log.target || '—'}
                  </td>
                  <td className="py-2.5 px-4 text-slate-400">{log.details || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
