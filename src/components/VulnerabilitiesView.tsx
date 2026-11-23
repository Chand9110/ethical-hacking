import { useEffect, useState } from 'react';
import { Code2, Filter, Search, ShieldCheck } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { RemediationStatus, SeverityLevel, UserRole, VulnerabilityRecord } from '../types';
import { RemediationText, SeverityText } from './SeverityIndicator';

interface VulnerabilitiesViewProps {
  initialScanIdFilter: number | null;
  selectedVulnerability: VulnerabilityRecord | null;
  userRole: UserRole;
  onSelectVulnerability: (vuln: VulnerabilityRecord | null) => void;
  onStatusUpdated: () => void;
  onClearScanFilter: () => void;
}

export function VulnerabilitiesView({
  initialScanIdFilter,
  selectedVulnerability,
  userRole,
  onSelectVulnerability,
  onStatusUpdated,
  onClearScanFilter,
}: VulnerabilitiesViewProps) {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'All' | SeverityLevel>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | RemediationStatus>('All');
  const [updatingId, setUpdatingId] = useState<number | null>(null);
  const [error, setError] = useState('');

  const canMutate = userRole === 'admin' || userRole === 'analyst';

  const fetchVulnerabilities = async () => {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams();
      if (severityFilter !== 'All') params.set('severity', severityFilter);
      if (statusFilter !== 'All') params.set('status', statusFilter);
      if (initialScanIdFilter !== null) params.set('scanId', String(initialScanIdFilter));
      if (searchQuery.trim()) params.set('q', searchQuery.trim());

      const res = await apiFetch<{ vulnerabilities: VulnerabilityRecord[] }>(
        `/api/vulnerabilities?${params.toString()}`
      );
      setVulnerabilities(res.vulnerabilities);

      if (res.vulnerabilities.length > 0 && !selectedVulnerability) {
        onSelectVulnerability(res.vulnerabilities[0]);
      } else if (selectedVulnerability) {
        const refreshed = res.vulnerabilities.find((v) => v.id === selectedVulnerability.id);
        if (refreshed) onSelectVulnerability(refreshed);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load vulnerabilities.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchVulnerabilities();
  }, [severityFilter, statusFilter, initialScanIdFilter]);

  const handleStatusChange = async (vulnId: number, nextStatus: RemediationStatus) => {
    setUpdatingId(vulnId);
    setError('');
    try {
      await apiFetch(`/api/vulnerabilities/${vulnId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === vulnId ? { ...v, remediation_status: nextStatus } : v))
      );
      if (selectedVulnerability?.id === vulnId) {
        onSelectVulnerability({ ...selectedVulnerability, remediation_status: nextStatus });
      }
      onStatusUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status.');
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-5">
      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-[#0D1424] border border-slate-800/80 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          <div className="relative flex-1 min-w-[220px] max-w-sm">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void fetchVulnerabilities();
              }}
              placeholder="Search vulnerability, URL, or OWASP code..."
              className="w-full pl-8 pr-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="button"
            onClick={() => void fetchVulnerabilities()}
            className="px-3 py-2 text-xs font-medium rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors whitespace-nowrap cursor-pointer"
          >
            Apply Search
          </button>
          {initialScanIdFilter !== null && (
            <button
              type="button"
              onClick={onClearScanFilter}
              className="px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors whitespace-nowrap cursor-pointer"
            >
              Showing Scan #{initialScanIdFilter} · Clear Filter
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1 p-1 bg-[#070B14] border border-slate-800 rounded-lg">
            {(['All', 'Critical', 'High', 'Medium', 'Low'] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-cyan-500/15 text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'All' | RemediationStatus)}
              aria-label="Filter by remediation status"
              className="px-3 py-1.5 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Statuses</option>
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Resolved">Resolved</option>
              <option value="Accepted Risk">Accepted Risk</option>
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div role="alert" className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Master-Detail Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Findings List */}
        <div className="lg:col-span-5 rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800/80 bg-[#090F1D] flex items-center justify-between">
            <span className="text-xs font-medium text-slate-300">
              Detected Vulnerabilities
            </span>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              {vulnerabilities.length} item(s)
            </span>
          </div>

          <div className="divide-y divide-slate-800/60 max-h-[680px] overflow-y-auto">
            {loading ? (
              <div className="p-6 space-y-3">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-16 rounded-lg bg-slate-800/40 animate-pulse" />
                ))}
              </div>
            ) : vulnerabilities.length === 0 ? (
              <div className="p-10 text-center space-y-2">
                <ShieldCheck className="w-7 h-7 text-emerald-400 mx-auto" aria-hidden="true" />
                <p className="text-sm font-medium text-white">No Matching Vulnerabilities</p>
                <p className="text-xs text-slate-400">
                  Adjust your filters or run a new website scan.
                </p>
              </div>
            ) : (
              vulnerabilities.map((vuln) => {
                const isSelected = selectedVulnerability?.id === vuln.id;
                return (
                  <button
                    key={vuln.id}
                    type="button"
                    onClick={() => onSelectVulnerability(vuln)}
                    className={`w-full text-left p-4 transition-colors cursor-pointer ${
                      isSelected ? 'bg-cyan-500/10' : 'hover:bg-slate-800/30'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <SeverityText severity={vuln.severity} />
                      <RemediationText status={vuln.remediation_status} />
                    </div>
                    <p className="text-sm font-medium text-slate-100 leading-snug">
                      {vuln.name}
                    </p>
                    <div className="mt-1.5 flex items-center gap-2 text-[11px] text-slate-400 font-mono truncate">
                      <span>{vuln.website_name || `Scan #${vuln.scan_id}`}</span>
                      <span aria-hidden="true">·</span>
                      <span className="truncate">{vuln.affected_url}</span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Vulnerability Detail Inspector */}
        <div className="lg:col-span-7 rounded-xl bg-[#0D1424] border border-slate-800/80 p-6">
          {!selectedVulnerability ? (
            <div className="py-20 text-center text-xs text-slate-400">
              Select a vulnerability from the list to inspect evidence, security standard mappings, and remediation guidance.
            </div>
          ) : (
            <div className="space-y-6">
              {/* Header & Remediation Status */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-5 border-b border-slate-800/80">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-400">
                    <SeverityText severity={selectedVulnerability.severity} />
                    <span aria-hidden="true">·</span>
                    <span>{selectedVulnerability.category}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono">{selectedVulnerability.rule_code}</span>
                    <span aria-hidden="true">·</span>
                    <span>Confidence: {selectedVulnerability.confidence}</span>
                  </div>
                  <h2 className="font-display text-xl font-semibold text-white">
                    {selectedVulnerability.name}
                  </h2>
                  <p className="text-xs font-mono text-cyan-300 break-all">
                    {selectedVulnerability.affected_url}
                    {selectedVulnerability.parameter_name
                      ? ` (Target: ${selectedVulnerability.parameter_name})`
                      : ''}
                  </p>
                </div>

                <div className="shrink-0">
                  <label htmlFor="remediation-status-select" className="block text-[11px] text-slate-400 mb-1">
                    Remediation Status
                  </label>
                  <select
                    id="remediation-status-select"
                    disabled={!canMutate || updatingId === selectedVulnerability.id}
                    value={selectedVulnerability.remediation_status}
                    onChange={(e) =>
                      void handleStatusChange(
                        selectedVulnerability.id,
                        e.target.value as RemediationStatus
                      )
                    }
                    className="px-3 py-2 text-xs font-medium bg-[#070B14] border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
                  >
                    <option value="Open">Open</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Accepted Risk">Accepted Risk</option>
                  </select>
                </div>
              </div>

              {/* Standards Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                  <p className="text-[11px] text-slate-400">OWASP Top 10</p>
                  <p className="font-medium text-slate-200 mt-1">{selectedVulnerability.owasp_top10}</p>
                </div>
                <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                  <p className="text-[11px] text-slate-400">OWASP WSTG</p>
                  <p className="font-mono text-cyan-300 mt-1">{selectedVulnerability.owasp_wstg}</p>
                </div>
                <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                  <p className="text-[11px] text-slate-400">OWASP ASVS</p>
                  <p className="font-mono text-slate-200 mt-1">{selectedVulnerability.owasp_asvs}</p>
                </div>
                <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                  <p className="text-[11px] text-slate-400">NIST Reference</p>
                  <p className="font-mono text-slate-200 mt-1">{selectedVulnerability.nist_800_115}</p>
                </div>
              </div>

              {/* Description & Evidence */}
              <div className="space-y-4">
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 mb-1.5">Description</h3>
                  <p className="text-sm text-slate-300 leading-relaxed">
                    {selectedVulnerability.description}
                  </p>
                </div>

                <div>
                  <h3 className="text-xs font-semibold text-slate-300 mb-1.5">Detection Evidence</h3>
                  <pre className="p-3.5 rounded-lg bg-[#070B14] border border-slate-800 text-xs font-mono text-amber-300 whitespace-pre-wrap break-all">
                    {selectedVulnerability.evidence}
                  </pre>
                </div>

                <div>
                  <h3 className="text-xs font-semibold text-slate-300 mb-1.5">Potential Impact</h3>
                  <p className="text-sm text-slate-300 leading-relaxed">
                    {selectedVulnerability.potential_impact}
                  </p>
                </div>
              </div>

              {/* Recommended Solution & Secure Coding */}
              <div className="pt-5 border-t border-slate-800/80 space-y-4">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-display text-base font-semibold text-cyan-300">
                    Recommended Solution: {selectedVulnerability.rec_title || 'Remediation Guidance'}
                  </h3>
                  {selectedVulnerability.rec_priority && (
                    <span className="text-xs font-mono text-slate-400">
                      Priority: {selectedVulnerability.rec_priority}
                    </span>
                  )}
                </div>

                {selectedVulnerability.remediation_steps && (
                  <div>
                    <p className="text-xs font-medium text-slate-400 mb-1">Practical Remediation Steps</p>
                    <p className="text-sm text-slate-200 whitespace-pre-line leading-relaxed">
                      {selectedVulnerability.remediation_steps}
                    </p>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {selectedVulnerability.preventive_measures && (
                    <div className="p-3.5 rounded-lg bg-[#070B14] border border-slate-800/80">
                      <p className="text-xs font-medium text-slate-300 mb-1">Preventive Measures</p>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {selectedVulnerability.preventive_measures}
                      </p>
                    </div>
                  )}
                  {selectedVulnerability.secure_coding_practice && (
                    <div className="p-3.5 rounded-lg bg-[#070B14] border border-slate-800/80">
                      <p className="text-xs font-medium text-slate-300 mb-1">Secure Coding Practice</p>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {selectedVulnerability.secure_coding_practice}
                      </p>
                    </div>
                  )}
                </div>

                {selectedVulnerability.code_example && (
                  <div>
                    <div className="flex items-center gap-1.5 text-xs font-medium text-slate-300 mb-1.5">
                      <Code2 className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
                      Secure Implementation Pattern
                    </div>
                    <pre className="p-3.5 rounded-lg bg-[#070B14] border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto">
                      {selectedVulnerability.code_example}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
