import { useMemo, useState } from 'react';
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { Download, Eye, FileText, RefreshCw, Search } from 'lucide-react';
import { apiFetch, downloadCsvReport } from '../lib/api';
import { generatePdfSecurityReport, type PdfReportPayload } from '../lib/pdfExport';
import type { OverviewResponse, UserRole } from '../types';
import { AnimatedNumber, ScanStatusText, scoreColorClass } from './SeverityIndicator';

ChartJS.register(
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend
);

interface DashboardOverviewProps {
  overview: OverviewResponse | null;
  loading: boolean;
  userRole: UserRole;
  onNavigateToScan: (scanId?: number) => void;
  onInspectScanVulnerabilities: (scanId: number) => void;
  onRefresh: () => void;
}

export function DashboardOverview({
  overview,
  loading,
  userRole,
  onNavigateToScan,
  onInspectScanVulnerabilities,
  onRefresh,
}: DashboardOverviewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'completed' | 'running' | 'stopped' | 'failed'>('all');
  const [busyScanId, setBusyScanId] = useState<number | null>(null);
  const [actionError, setActionError] = useState('');

  const canMutate = userRole === 'admin' || userRole === 'analyst';

  const filteredScans = useMemo(() => {
    if (!overview) return [];
    return overview.recentScans.filter((scan) => {
      if (statusFilter !== 'all' && scan.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          scan.website_name.toLowerCase().includes(q) ||
          scan.base_url.toLowerCase().includes(q) ||
          String(scan.id).includes(q)
        );
      }
      return true;
    });
  }, [overview, searchQuery, statusFilter]);

  const handleRescan = async (scanId: number) => {
    setActionError('');
    setBusyScanId(scanId);
    try {
      const res = await apiFetch<{ scanId: number }>(`/api/scans/${scanId}/rescan`, {
        method: 'POST',
      });
      onRefresh();
      onNavigateToScan(res.scanId);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Unable to start rescan.');
    } finally {
      setBusyScanId(null);
    }
  };

  const handleDownloadPdf = async (scanId: number) => {
    setActionError('');
    setBusyScanId(scanId);
    try {
      const payload = await apiFetch<PdfReportPayload>('/api/reports', {
        method: 'POST',
        body: JSON.stringify({ scanId, format: 'PDF' }),
      });
      generatePdfSecurityReport(payload);
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'PDF generation failed.');
    } finally {
      setBusyScanId(null);
    }
  };

  const handleDownloadCsv = async (scanId: number, siteName: string) => {
    setActionError('');
    setBusyScanId(scanId);
    try {
      await downloadCsvReport(scanId, siteName.toLowerCase().replace(/[^a-z0-9]+/g, '-'));
      onRefresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'CSV export failed.');
    } finally {
      setBusyScanId(null);
    }
  };

  if (loading && !overview) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 rounded-xl bg-[#0D1424] border border-slate-800/80 animate-pulse" />
          ))}
        </div>
        <div className="h-80 rounded-xl bg-[#0D1424] border border-slate-800/80 animate-pulse" />
      </div>
    );
  }

  const m = overview?.metrics ?? {
    totalWebsitesScanned: 0,
    totalVulnerabilitiesDetected: 0,
    activeVulnerabilities: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    overallSecurityScore: 0,
  };

  const doughnutData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [m.criticalCount, m.highCount, m.mediumCount, m.lowCount],
        backgroundColor: ['#F43F5E', '#F97316', '#F59E0B', '#06B6D4'],
        borderColor: '#0D1424',
        borderWidth: 2,
      },
    ],
  };

  const trendLabels = (overview?.trendHistory ?? []).map(
    (t) => `#${t.id} ${t.website_name.split(' ')[0]}`
  );

  const trendData = {
    labels: trendLabels,
    datasets: [
      {
        label: 'Security Score',
        data: (overview?.trendHistory ?? []).map((t) => t.security_score ?? 0),
        borderColor: '#22D3EE',
        backgroundColor: 'rgba(34, 211, 238, 0.12)',
        fill: true,
        tension: 0.3,
        pointRadius: 4,
        pointBackgroundColor: '#22D3EE',
      },
      {
        label: 'Findings Count',
        data: (overview?.trendHistory ?? []).map((t) => t.vulnerabilities_found),
        borderColor: '#F43F5E',
        backgroundColor: 'rgba(244, 63, 94, 0.06)',
        fill: false,
        tension: 0.3,
        pointRadius: 4,
        pointBackgroundColor: '#F43F5E',
      },
    ],
  };

  const owaspLabels = (overview?.owaspBreakdown ?? []).map((o) => o.category.replace(' - ', '\n'));
  const owaspBarData = {
    labels: owaspLabels,
    datasets: [
      {
        label: 'Findings',
        data: (overview?.owaspBreakdown ?? []).map((o) => o.count),
        backgroundColor: 'rgba(6, 182, 212, 0.72)',
        borderColor: '#22D3EE',
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  };

  return (
    <div className="space-y-6">
      {actionError && (
        <div role="alert" className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
          {actionError}
        </div>
      )}

      {/* Primary KPI Grid (7 numeric KPIs; 8th is Recent Scan History table below) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80">
          <p className="text-xs font-medium text-slate-400">Overall Security Score</p>
          <div className="mt-2 flex items-baseline justify-between">
            <span className={`text-3xl font-semibold ${scoreColorClass(m.overallSecurityScore)}`}>
              <AnimatedNumber value={m.overallSecurityScore} suffix="/100" />
            </span>
            <span className="text-xs text-slate-400">Across latest scans</span>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80">
          <p className="text-xs font-medium text-slate-400">Total Websites Scanned</p>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-3xl font-semibold text-white">
              <AnimatedNumber value={m.totalWebsitesScanned} />
            </span>
            <span className="text-xs text-cyan-400">Authorized targets</span>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80">
          <p className="text-xs font-medium text-slate-400">Total Vulnerabilities Detected</p>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-3xl font-semibold text-white">
              <AnimatedNumber value={m.totalVulnerabilitiesDetected} />
            </span>
            <span className="text-xs text-slate-400 tabular-nums">
              {m.activeVulnerabilities} unresolved
            </span>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80">
          <p className="text-xs font-medium text-slate-400">Severity Breakdown (Active)</p>
          <div className="mt-3 grid grid-cols-4 gap-2 text-center">
            <div>
              <p className="text-lg font-semibold text-rose-400">
                <AnimatedNumber value={m.criticalCount} />
              </p>
              <p className="text-[11px] text-slate-400">Critical</p>
            </div>
            <div>
              <p className="text-lg font-semibold text-orange-400">
                <AnimatedNumber value={m.highCount} />
              </p>
              <p className="text-[11px] text-slate-400">High</p>
            </div>
            <div>
              <p className="text-lg font-semibold text-amber-400">
                <AnimatedNumber value={m.mediumCount} />
              </p>
              <p className="text-[11px] text-slate-400">Medium</p>
            </div>
            <div>
              <p className="text-lg font-semibold text-cyan-400">
                <AnimatedNumber value={m.lowCount} />
              </p>
              <p className="text-[11px] text-slate-400">Low</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-4 p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 flex flex-col">
          <h3 className="font-display text-sm font-semibold text-white mb-1">
            Active Severity Distribution
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Unresolved findings grouped by impact level
          </p>
          <div className="h-56 flex items-center justify-center">
            <Doughnut
              data={doughnutData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '66%',
                plugins: {
                  legend: {
                    position: 'bottom',
                    labels: { color: '#CBD5E1', boxWidth: 10, padding: 14, font: { size: 11 } },
                  },
                },
              }}
            />
          </div>
        </div>

        <div className="lg:col-span-8 p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 flex flex-col">
          <h3 className="font-display text-sm font-semibold text-white mb-1">
            Security Score & Vulnerability Trend
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Posture progression across completed storefront scans
          </p>
          <div className="h-56">
            <Line
              data={trendData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: {
                    beginAtZero: true,
                    max: 100,
                    grid: { color: 'rgba(148, 163, 184, 0.08)' },
                    ticks: { color: '#94A3B8', font: { size: 11 } },
                  },
                  x: {
                    grid: { display: false },
                    ticks: { color: '#94A3B8', font: { size: 11 } },
                  },
                },
                plugins: {
                  legend: {
                    position: 'top',
                    align: 'end',
                    labels: { color: '#CBD5E1', boxWidth: 10, font: { size: 11 } },
                  },
                },
              }}
            />
          </div>
        </div>
      </div>

      {/* OWASP Top 10 Distribution */}
      <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className="font-display text-sm font-semibold text-white">
              OWASP Top 10 (2021) Category Distribution
            </h3>
            <p className="text-xs text-slate-400">
              Aggregate rule detections mapped to OWASP security categories
            </p>
          </div>
        </div>
        <div className="h-52">
          <Bar
            data={owaspBarData}
            options={{
              responsive: true,
              maintainAspectRatio: false,
              indexAxis: 'y',
              scales: {
                x: {
                  beginAtZero: true,
                  grid: { color: 'rgba(148, 163, 184, 0.08)' },
                  ticks: { color: '#94A3B8', precision: 0, font: { size: 11 } },
                },
                y: {
                  grid: { display: false },
                  ticks: { color: '#CBD5E1', font: { size: 11 } },
                },
              },
              plugins: {
                legend: { display: false },
              },
            }}
          />
        </div>
      </div>

      {/* Recent Scan History Table */}
      <div className="rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="font-display text-base font-semibold text-white">Recent Scan History</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect crawled pages, re-run assessments after fixes, or export compliance reports
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search target or ID..."
                className="pl-8 pr-3 py-1.5 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-1 p-1 bg-[#070B14] border border-slate-800 rounded-lg">
              {(['all', 'completed', 'running', 'stopped'] as const).map((status) => (
                <button
                  key={status}
                  type="button"
                  onClick={() => setStatusFilter(status)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md capitalize transition-colors whitespace-nowrap cursor-pointer ${
                    statusFilter === status
                      ? 'bg-cyan-500/15 text-cyan-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800/80 text-[11px] font-medium text-slate-400 bg-[#090F1D]">
                <th className="py-3 px-4">Scan</th>
                <th className="py-3 px-4">Target Website</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Pages</th>
                <th className="py-3 px-4 text-right">Findings</th>
                <th className="py-3 px-4 text-right">Score</th>
                <th className="py-3 px-4">Date</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-400">
                    No scans match your current filters. Start a new scan to populate history.
                  </td>
                </tr>
              ) : (
                filteredScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/25 transition-colors">
                    <td className="py-3 px-4 font-mono tabular-nums text-slate-400">#{scan.id}</td>
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-100">{scan.website_name}</div>
                      <div className="text-[11px] text-slate-400 font-mono truncate max-w-[240px]">
                        {scan.base_url}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <ScanStatusText status={scan.status} />
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                      {scan.pages_scanned}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                      {scan.vulnerabilities_found}
                    </td>
                    <td className={`py-3 px-4 text-right font-mono tabular-nums font-semibold ${scoreColorClass(scan.security_score)}`}>
                      {scan.security_score !== null ? `${scan.security_score}/100` : '—'}
                    </td>
                    <td className="py-3 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {scan.started_at.slice(0, 16)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => onInspectScanVulnerabilities(scan.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-slate-800/70 hover:bg-slate-700 text-slate-200 transition-colors whitespace-nowrap cursor-pointer"
                          title="View vulnerabilities for this scan"
                        >
                          <Eye className="w-3.5 h-3.5" aria-hidden="true" />
                          Findings
                        </button>
                        {canMutate && (
                          <button
                            type="button"
                            disabled={busyScanId === scan.id || scan.status === 'running'}
                            onClick={() => handleRescan(scan.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/25 disabled:opacity-40 transition-colors whitespace-nowrap cursor-pointer"
                            title="Run a fresh rescan"
                          >
                            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
                            Rescan
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={busyScanId === scan.id || scan.status !== 'completed'}
                          onClick={() => handleDownloadPdf(scan.id)}
                          className="inline-flex items-center gap-1 px-2 py-1.5 rounded-md bg-slate-800/70 hover:bg-slate-700 text-slate-200 disabled:opacity-40 transition-colors whitespace-nowrap cursor-pointer"
                          title="Download PDF report"
                        >
                          <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                          PDF
                        </button>
                        <button
                          type="button"
                          disabled={busyScanId === scan.id || scan.status !== 'completed'}
                          onClick={() => handleDownloadCsv(scan.id, scan.website_name)}
                          className="inline-flex items-center gap-1 px-2 py-1.5 rounded-md bg-slate-800/70 hover:bg-slate-700 text-slate-200 disabled:opacity-40 transition-colors whitespace-nowrap cursor-pointer"
                          title="Export CSV report"
                        >
                          <Download className="w-3.5 h-3.5" aria-hidden="true" />
                          CSV
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
