import { useEffect, useState } from 'react';
import { Download, FileText } from 'lucide-react';
import { apiFetch, downloadCsvReport } from '../lib/api';
import { generatePdfSecurityReport, type PdfReportPayload } from '../lib/pdfExport';
import type { GeneratedReportRecord, ScanRecord } from '../types';
import { scoreColorClass } from './SeverityIndicator';

export function ReportsArchiveView() {
  const [reports, setReports] = useState<GeneratedReportRecord[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [repRes, scanRes] = await Promise.all([
        apiFetch<{ reports: GeneratedReportRecord[] }>('/api/reports'),
        apiFetch<{ scans: ScanRecord[] }>('/api/scans'),
      ]);
      setReports(repRes.reports);
      const completed = scanRes.scans.filter((s) => s.status === 'completed');
      setScans(completed);
      if (completed.length > 0 && !selectedScanId) {
        setSelectedScanId(completed[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load reports archive.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const handleGeneratePdf = async (scanId: number) => {
    setGenerating(true);
    setError('');
    try {
      const payload = await apiFetch<PdfReportPayload>('/api/reports', {
        method: 'POST',
        body: JSON.stringify({ scanId, format: 'PDF' }),
      });
      generatePdfSecurityReport(payload);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate PDF report.');
    } finally {
      setGenerating(false);
    }
  };

  const handleGenerateCsv = async (scanId: number) => {
    setGenerating(true);
    setError('');
    try {
      await downloadCsvReport(scanId, 'aegis-assessment');
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export CSV report.');
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="flex-1 max-w-xl">
          <label htmlFor="report-scan-select" className="block text-xs font-medium text-slate-300 mb-1.5">
            Generate Report From Completed Scan
          </label>
          <select
            id="report-scan-select"
            value={selectedScanId ?? ''}
            onChange={(e) => setSelectedScanId(Number(e.target.value))}
            className="w-full px-3.5 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                Scan #{s.id} · {s.website_name} · Score {s.security_score ?? 0}/100 ({s.vulnerabilities_found} findings)
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={!selectedScanId || generating}
            onClick={() => selectedScanId && void handleGeneratePdf(selectedScanId)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-45 text-slate-950 font-semibold text-xs transition-colors whitespace-nowrap cursor-pointer"
          >
            <FileText className="w-4 h-4" aria-hidden="true" />
            Generate PDF Report
          </button>
          <button
            type="button"
            disabled={!selectedScanId || generating}
            onClick={() => selectedScanId && void handleGenerateCsv(selectedScanId)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-45 text-slate-100 font-medium text-xs transition-colors whitespace-nowrap cursor-pointer"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            Export CSV
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
          {error}
        </div>
      )}

      <div className="rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
        <div className="p-5 border-b border-slate-800/80">
          <h3 className="font-display text-base font-semibold text-white">Generated Assessment Reports</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Archive of PDF and CSV reports produced for compliance review and remediation tracking
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800/80 text-[11px] font-medium text-slate-400 bg-[#090F1D]">
                <th className="py-3 px-4">Report</th>
                <th className="py-3 px-4">Target Website</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4 text-right">Findings</th>
                <th className="py-3 px-4 text-right">Score</th>
                <th className="py-3 px-4">Generated</th>
                <th className="py-3 px-4 text-right">Download Again</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-400">
                    Loading report history...
                  </td>
                </tr>
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-400">
                    No reports generated yet. Select a completed scan above to generate your first report.
                  </td>
                </tr>
              ) : (
                reports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-slate-800/25 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-100">{rep.report_title}</div>
                      <div className="text-[11px] text-slate-400">
                        Scan #{rep.scan_id} · {rep.generated_by_name || 'System'}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{rep.website_name}</td>
                    <td className="py-3 px-4 font-mono text-cyan-300">{rep.format}</td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                      {rep.vulnerability_count}
                    </td>
                    <td className={`py-3 px-4 text-right font-mono tabular-nums font-semibold ${scoreColorClass(rep.security_score)}`}>
                      {rep.security_score}/100
                    </td>
                    <td className="py-3 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {rep.generated_at.slice(0, 16)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        disabled={generating}
                        onClick={() =>
                          rep.format === 'CSV'
                            ? void handleGenerateCsv(rep.scan_id)
                            : void handleGeneratePdf(rep.scan_id)
                        }
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors whitespace-nowrap cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" aria-hidden="true" />
                        Download {rep.format}
                      </button>
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
