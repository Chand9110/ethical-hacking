import { useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import { ArrowRight, CheckCircle2, TrendingUp } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { ScanRecord } from '../types';
import { scoreColorClass } from './SeverityIndicator';

interface ComparisonData {
  scanA: ScanRecord & { overall_score?: number };
  scanB: ScanRecord & { overall_score?: number };
  resolvedFindings: { rule_code: string; name: string; severity: string; affected_url: string }[];
  newFindings: { rule_code: string; name: string; severity: string; affected_url: string }[];
  persistentFindings: { rule_code: string; name: string; severity: string; affected_url: string }[];
}

export function ComparisonView() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [scanAId, setScanAId] = useState<number | null>(null);
  const [scanBId, setScanBId] = useState<number | null>(null);
  const [comparison, setComparison] = useState<ComparisonData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch<{ scans: ScanRecord[] }>('/api/scans')
      .then((res) => {
        const completed = res.scans.filter((s) => s.status === 'completed');
        setScans(completed);
        if (completed.length >= 2) {
          setScanAId(completed[1].id);
          setScanBId(completed[0].id);
        } else if (completed.length === 1) {
          setScanAId(completed[0].id);
          setScanBId(completed[0].id);
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load scans.'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!scanAId || !scanBId) return;
    apiFetch<ComparisonData>(`/api/comparison?scanA=${scanAId}&scanB=${scanBId}`)
      .then(setComparison)
      .catch((err) => setError(err instanceof Error ? err.message : 'Unable to compare scans.'));
  }, [scanAId, scanBId]);

  if (loading) {
    return <div className="h-72 rounded-xl bg-[#0D1424] border border-slate-800/80 animate-pulse" />;
  }

  if (scans.length === 0) {
    return (
      <div className="p-10 rounded-xl bg-[#0D1424] border border-slate-800/80 text-center text-sm text-slate-400">
        Complete at least two scans to compare security posture and remediation delta.
      </div>
    );
  }

  const scoreA = comparison?.scanA.security_score ?? 0;
  const scoreB = comparison?.scanB.security_score ?? 0;
  const scoreDelta = scoreB - scoreA;

  const chartData = comparison
    ? {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Security Score'],
        datasets: [
          {
            label: `Baseline (#${comparison.scanA.id} ${comparison.scanA.website_name})`,
            data: [
              comparison.scanA.critical_count ?? 0,
              comparison.scanA.high_count ?? 0,
              comparison.scanA.medium_count ?? 0,
              comparison.scanA.low_count ?? 0,
              scoreA,
            ],
            backgroundColor: 'rgba(148, 163, 184, 0.55)',
            borderRadius: 4,
          },
          {
            label: `Target (#${comparison.scanB.id} ${comparison.scanB.website_name})`,
            data: [
              comparison.scanB.critical_count ?? 0,
              comparison.scanB.high_count ?? 0,
              comparison.scanB.medium_count ?? 0,
              comparison.scanB.low_count ?? 0,
              scoreB,
            ],
            backgroundColor: 'rgba(34, 211, 238, 0.78)',
            borderRadius: 4,
          },
        ],
      }
    : null;

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 flex-1">
          <div>
            <label htmlFor="compare-a" className="block text-xs font-medium text-slate-300 mb-1.5">
              Baseline Scan (A)
            </label>
            <select
              id="compare-a"
              value={scanAId ?? ''}
              onChange={(e) => setScanAId(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} · {s.website_name} ({s.security_score ?? 0}/100)
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="compare-b" className="block text-xs font-medium text-slate-300 mb-1.5">
              Comparison / Rescan (B)
            </label>
            <select
              id="compare-b"
              value={scanBId ?? ''}
              onChange={(e) => setScanBId(Number(e.target.value))}
              className="w-full px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} · {s.website_name} ({s.security_score ?? 0}/100)
                </option>
              ))}
            </select>
          </div>
        </div>

        {comparison && (
          <div className="flex items-center gap-4 px-4 py-2.5 rounded-lg bg-[#070B14] border border-slate-800/80">
            <div>
              <p className="text-[11px] text-slate-400">Baseline</p>
              <p className={`text-lg font-mono tabular-nums font-semibold ${scoreColorClass(scoreA)}`}>
                {scoreA}/100
              </p>
            </div>
            <ArrowRight className="w-4 h-4 text-slate-500" aria-hidden="true" />
            <div>
              <p className="text-[11px] text-slate-400">Comparison</p>
              <p className={`text-lg font-mono tabular-nums font-semibold ${scoreColorClass(scoreB)}`}>
                {scoreB}/100
              </p>
            </div>
            <div className="pl-3 border-l border-slate-800">
              <p className="text-[11px] text-slate-400">Delta</p>
              <p
                className={`text-lg font-mono tabular-nums font-semibold ${
                  scoreDelta > 0
                    ? 'text-emerald-400'
                    : scoreDelta < 0
                      ? 'text-rose-400'
                      : 'text-slate-300'
                }`}
              >
                {scoreDelta > 0 ? `+${scoreDelta}` : scoreDelta}
              </p>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div role="alert" className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
          {error}
        </div>
      )}

      {comparison && chartData && (
        <>
          <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-cyan-400" aria-hidden="true" />
              <h3 className="font-display text-sm font-semibold text-white">
                Side-by-Side Security Metrics Comparison
              </h3>
            </div>
            <div className="h-64">
              <Bar
                data={chartData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  scales: {
                    y: {
                      beginAtZero: true,
                      grid: { color: 'rgba(148, 163, 184, 0.08)' },
                      ticks: { color: '#94A3B8', font: { size: 11 } },
                    },
                    x: {
                      grid: { display: false },
                      ticks: { color: '#CBD5E1', font: { size: 11 } },
                    },
                  },
                  plugins: {
                    legend: {
                      position: 'top',
                      labels: { color: '#CBD5E1', boxWidth: 10, font: { size: 11 } },
                    },
                  },
                }}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="font-display text-sm font-semibold text-emerald-400">
                  Resolved Since Baseline
                </h4>
                <span className="font-mono tabular-nums text-xs text-slate-400">
                  {comparison.resolvedFindings.length}
                </span>
              </div>
              {comparison.resolvedFindings.length === 0 ? (
                <p className="text-xs text-slate-500">No resolved findings between selected scans.</p>
              ) : (
                <ul className="space-y-2.5 text-xs">
                  {comparison.resolvedFindings.map((f, idx) => (
                    <li key={`${f.rule_code}-${idx}`} className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800/80">
                      <div className="flex items-center gap-1.5 text-emerald-300 font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                        {f.name}
                      </div>
                      <p className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                        {f.rule_code} · {f.affected_url}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="font-display text-sm font-semibold text-rose-400">
                  Newly Detected in Target
                </h4>
                <span className="font-mono tabular-nums text-xs text-slate-400">
                  {comparison.newFindings.length}
                </span>
              </div>
              {comparison.newFindings.length === 0 ? (
                <p className="text-xs text-slate-500">No new regressions introduced.</p>
              ) : (
                <ul className="space-y-2.5 text-xs">
                  {comparison.newFindings.map((f, idx) => (
                    <li key={`${f.rule_code}-${idx}`} className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800/80">
                      <p className="text-rose-300 font-medium">{f.name}</p>
                      <p className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                        {f.severity} · {f.rule_code}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="font-display text-sm font-semibold text-amber-300">
                  Persistent Findings
                </h4>
                <span className="font-mono tabular-nums text-xs text-slate-400">
                  {comparison.persistentFindings.length}
                </span>
              </div>
              {comparison.persistentFindings.length === 0 ? (
                <p className="text-xs text-slate-500">Zero persistent findings remaining.</p>
              ) : (
                <ul className="space-y-2.5 text-xs">
                  {comparison.persistentFindings.map((f, idx) => (
                    <li key={`${f.rule_code}-${idx}`} className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800/80">
                      <p className="text-slate-200 font-medium">{f.name}</p>
                      <p className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                        {f.severity} · {f.rule_code}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
