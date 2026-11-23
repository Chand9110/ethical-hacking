import { useEffect, useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  Download,
  FileText,
  Globe,
  Play,
  ShieldCheck,
  Square,
  Wrench,
} from 'lucide-react';
import { apiFetch, downloadCsvReport } from '../lib/api';
import { generatePdfSecurityReport, type PdfReportPayload } from '../lib/pdfExport';
import type {
  RiskAssessmentRecord,
  ScanRecord,
  ScannedPageRecord,
  UserRole,
  VulnerabilityRecord,
} from '../types';
import { ScanStatusText, SeverityText, scoreColorClass } from './SeverityIndicator';

interface ScanWorkspaceProps {
  activeScanId: number | null;
  userRole: UserRole;
  onScanStarted: (scanId: number) => void;
  onScanFinished: () => void;
  onSelectVulnerability: (vuln: VulnerabilityRecord) => void;
}

interface ScanDetailResponse {
  scan: ScanRecord;
  pages: ScannedPageRecord[];
  riskAssessment: RiskAssessmentRecord | null;
  vulnerabilities: VulnerabilityRecord[];
}

const DEMO_TARGET_URL = 'https://demo-store.aegiscommerce.test';

export function ScanWorkspace({
  activeScanId,
  userRole,
  onScanStarted,
  onScanFinished,
  onSelectVulnerability,
}: ScanWorkspaceProps) {
  const [url, setUrl] = useState(DEMO_TARGET_URL);
  const [siteName, setSiteName] = useState('Meridian Mart (Demo Store)');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [scanMode, setScanMode] = useState<'quick' | 'standard' | 'comprehensive'>('standard');
  const [maxPages, setMaxPages] = useState(10);
  const [checkSqli, setCheckSqli] = useState(true);
  const [checkXss, setCheckXss] = useState(true);
  const [checkHeaders, setCheckHeaders] = useState(true);
  const [checkCookies, setCheckCookies] = useState(true);
  const [checkMisconfig, setCheckMisconfig] = useState(true);

  const [demoPosture, setDemoPosture] = useState<'vulnerable' | 'hardened'>('vulnerable');
  const [togglingDemo, setTogglingDemo] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [scanDetail, setScanDetail] = useState<ScanDetailResponse | null>(null);
  const [resultTab, setResultTab] = useState<'findings' | 'pages'>('findings');

  const canRunScans = userRole === 'admin' || userRole === 'analyst';

  useEffect(() => {
    apiFetch<{ posture: 'vulnerable' | 'hardened' }>('/api/demo-store')
      .then((res) => setDemoPosture(res.posture))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!activeScanId) return;

    let cancelled = false;
    let timerId: number | undefined;

    const loadScan = async () => {
      try {
        const data = await apiFetch<ScanDetailResponse>(`/api/scans/${activeScanId}`);
        if (cancelled) return;
        setScanDetail(data);

        if (data.scan.status === 'running' || data.scan.status === 'queued') {
          timerId = window.setTimeout(loadScan, 550);
        } else {
          onScanFinished();
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to fetch scan progress.');
        }
      }
    };

    void loadScan();
    return () => {
      cancelled = true;
      if (timerId) window.clearTimeout(timerId);
    };
  }, [activeScanId]);

  const handleLoadDemo = () => {
    setUrl(DEMO_TARGET_URL);
    setSiteName('Meridian Mart (Demo Store)');
    setError('');
  };

  const handleToggleDemoPosture = async (next: 'vulnerable' | 'hardened') => {
    setTogglingDemo(true);
    setError('');
    try {
      const res = await apiFetch<{ posture: 'vulnerable' | 'hardened' }>('/api/demo-store/posture', {
        method: 'POST',
        body: JSON.stringify({ posture: next }),
      });
      setDemoPosture(res.posture);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to update demo store posture.');
    } finally {
      setTogglingDemo(false);
    }
  };

  const handleStartScan = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    if (!authorizationConfirmed) {
      setError('You must confirm explicit ownership or written testing authorization before scanning.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await apiFetch<{ scanId: number }>('/api/scans/start', {
        method: 'POST',
        body: JSON.stringify({
          url,
          name: siteName,
          authorizationConfirmed,
          scanMode,
          maxPages,
          checkSqli,
          checkXss,
          checkHeaders,
          checkCookies,
          checkMisconfig,
        }),
      });
      onScanStarted(res.scanId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to initiate scan.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleStopScan = async () => {
    if (!scanDetail) return;
    try {
      await apiFetch(`/api/scans/${scanDetail.scan.id}/stop`, { method: 'POST' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop scan.');
    }
  };

  const handlePdfExport = async () => {
    if (!scanDetail) return;
    try {
      const payload = await apiFetch<PdfReportPayload>('/api/reports', {
        method: 'POST',
        body: JSON.stringify({ scanId: scanDetail.scan.id, format: 'PDF' }),
      });
      generatePdfSecurityReport(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to export PDF report.');
    }
  };

  const isRunning =
    scanDetail?.scan.status === 'running' || scanDetail?.scan.status === 'queued';

  const progressPercent = scanDetail
    ? scanDetail.scan.status === 'completed'
      ? 100
      : Math.min(95, Math.round((scanDetail.scan.pages_scanned / Math.max(1, scanDetail.scan.max_pages)) * 100))
    : 0;

  return (
    <div className="space-y-6">
      {/* Top Configuration Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Scan Target Form */}
        <form
          onSubmit={handleStartScan}
          className="lg:col-span-7 p-6 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-5"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="font-display text-lg font-semibold text-white">
                Configure Authorized Target Scan
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Non-destructive crawling, passive header/cookie inspection, and safe parameter checks
              </p>
            </div>
            <button
              type="button"
              onClick={handleLoadDemo}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Load Demo Store
            </button>
          </div>

          {error && (
            <div role="alert" className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="sm:col-span-2">
              <label htmlFor="scan-url" className="block text-xs font-medium text-slate-300 mb-1.5">
                E-Commerce Website URL
              </label>
              <div className="relative">
                <Globe className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" aria-hidden="true" />
                <input
                  id="scan-url"
                  type="url"
                  required
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-authorized-store.com"
                  className="w-full pl-10 pr-4 py-2.5 text-sm font-mono bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <p className="mt-1.5 text-[11px] text-slate-500">
                Private IP ranges, localhost, and internal cloud metadata endpoints are automatically blocked.
              </p>
            </div>

            <div>
              <label htmlFor="scan-name" className="block text-xs font-medium text-slate-300 mb-1.5">
                Storefront Label
              </label>
              <input
                id="scan-name"
                type="text"
                value={siteName}
                onChange={(e) => setSiteName(e.target.value)}
                placeholder="Production Storefront"
                className="w-full px-3.5 py-2 text-sm bg-[#070B14] border border-slate-800 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label htmlFor="scan-mode" className="block text-xs font-medium text-slate-300 mb-1.5">
                Scan Profile & Max Pages ({maxPages})
              </label>
              <div className="flex items-center gap-3">
                <select
                  id="scan-mode"
                  value={scanMode}
                  onChange={(e) => setScanMode(e.target.value as 'quick' | 'standard' | 'comprehensive')}
                  className="px-3 py-2 text-xs bg-[#070B14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="comprehensive">Comprehensive</option>
                </select>
                <input
                  type="range"
                  min={2}
                  max={25}
                  value={maxPages}
                  onChange={(e) => setMaxPages(Number(e.target.value))}
                  aria-label="Maximum pages to crawl"
                  className="flex-1 accent-cyan-400"
                />
              </div>
            </div>
          </div>

          {/* Check Modules */}
          <div>
            <p className="text-xs font-medium text-slate-300 mb-2.5">Security Assessment Modules</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              {[
                { label: 'Non-Destructive SQLi Error Checks', checked: checkSqli, set: setCheckSqli },
                { label: 'Controlled XSS Reflection Checks', checked: checkXss, set: setCheckXss },
                { label: 'OWASP Security Headers Audit', checked: checkHeaders, set: setCheckHeaders },
                { label: 'Cookie Attributes (HttpOnly/Secure)', checked: checkCookies, set: setCheckCookies },
                { label: 'CSRF, Mixed Content & Misconfigs', checked: checkMisconfig, set: setCheckMisconfig },
              ].map((item) => (
                <label
                  key={item.label}
                  className="flex items-center gap-2.5 p-2.5 rounded-lg bg-[#070B14] border border-slate-800/80 cursor-pointer hover:border-slate-700"
                >
                  <input
                    type="checkbox"
                    checked={item.checked}
                    onChange={(e) => item.set(e.target.checked)}
                    className="rounded border-slate-700 accent-cyan-500"
                  />
                  <span className="text-slate-200">{item.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Authorization Checkbox */}
          <label className="flex items-start gap-3 p-3.5 rounded-lg bg-[#090F1D] border border-slate-800 cursor-pointer">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 accent-cyan-500"
            />
            <span className="text-xs text-slate-300 leading-relaxed">
              I confirm that I own this e-commerce website or hold explicit written permission to conduct automated, non-destructive security testing against this target.
            </span>
          </label>

          {/* Actions */}
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              type="submit"
              disabled={!canRunScans || submitting || isRunning}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-45 text-slate-950 font-semibold text-sm transition-colors whitespace-nowrap cursor-pointer"
            >
              <Play className="w-4 h-4" aria-hidden="true" />
              {submitting ? 'Starting Scan...' : 'Start Scan'}
            </button>

            <button
              type="button"
              disabled={!canRunScans || !isRunning}
              onClick={handleStopScan}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/35 text-rose-300 disabled:opacity-35 font-medium text-sm transition-colors whitespace-nowrap cursor-pointer"
            >
              <Square className="w-4 h-4" aria-hidden="true" />
              Stop Scan
            </button>

            {!canRunScans && (
              <span className="text-xs text-amber-400">
                Viewer role is read-only. Ask an administrator for Analyst access to run scans.
              </span>
            )}
          </div>
        </form>

        {/* Right Panel: Live Status + Demo Store Posture Switch */}
        <div className="lg:col-span-5 space-y-5">
          {/* Demo Store Posture Control */}
          <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-3.5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="font-display text-sm font-semibold text-white">
                  Demo Target Environment (Meridian Mart)
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Toggle the simulated storefront between Vulnerable Baseline and Patched states to verify rescan detection.
                </p>
              </div>
              <Wrench className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" aria-hidden="true" />
            </div>

            <div className="flex items-center gap-1 p-1 bg-[#070B14] border border-slate-800 rounded-lg">
              <button
                type="button"
                disabled={!canRunScans || togglingDemo}
                onClick={() => handleToggleDemoPosture('vulnerable')}
                className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  demoPosture === 'vulnerable'
                    ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Vulnerable Baseline
              </button>
              <button
                type="button"
                disabled={!canRunScans || togglingDemo}
                onClick={() => handleToggleDemoPosture('hardened')}
                className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  demoPosture === 'hardened'
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Patched / Hardened
              </button>
            </div>
          </div>

          {/* Live Scan Progress Card */}
          <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-display text-sm font-semibold text-white">
                {scanDetail ? `Scan #${scanDetail.scan.id} Progress` : 'Live Scan Telemetry'}
              </h3>
              {scanDetail ? (
                <ScanStatusText status={scanDetail.scan.status} />
              ) : (
                <span className="text-xs text-slate-500">Idle</span>
              )}
            </div>

            {!scanDetail ? (
              <div className="py-8 text-center text-xs text-slate-400">
                Select an existing scan from the dashboard or start a scan on the left to observe live crawling progress.
              </div>
            ) : (
              <>
                <div>
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className="text-slate-400">Crawl Progress</span>
                    <span className="font-mono tabular-nums text-cyan-300">{progressPercent}%</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-[#070B14] overflow-hidden border border-slate-800">
                    <div
                      className="h-full bg-cyan-400 transition-all duration-300"
                      style={{ width: `${progressPercent}%` }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 pt-1">
                  <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                    <p className="text-[11px] text-slate-400">Pages Scanned</p>
                    <p className="text-xl font-semibold font-mono tabular-nums text-white mt-0.5">
                      {scanDetail.scan.pages_scanned}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                    <p className="text-[11px] text-slate-400">Vulnerabilities</p>
                    <p className="text-xl font-semibold font-mono tabular-nums text-rose-400 mt-0.5">
                      {scanDetail.scan.vulnerabilities_found}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80">
                    <p className="text-[11px] text-slate-400">Security Score</p>
                    <p className={`text-xl font-semibold font-mono tabular-nums mt-0.5 ${scoreColorClass(scanDetail.scan.security_score)}`}>
                      {scanDetail.scan.security_score !== null ? scanDetail.scan.security_score : '—'}
                    </p>
                  </div>
                </div>

                {scanDetail.scan.current_url && (
                  <div className="p-2.5 rounded-lg bg-[#070B14] border border-slate-800/80 text-[11px] font-mono text-slate-300 truncate">
                    Checking: {scanDetail.scan.current_url}
                  </div>
                )}

                {scanDetail.scan.error_message && (
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
                    {scanDetail.scan.error_message}
                  </div>
                )}

                {scanDetail.riskAssessment && (
                  <div className="p-3.5 rounded-lg bg-[#090F1D] border border-slate-800/80 space-y-2 text-xs">
                    <div className="flex items-center justify-between text-slate-300 font-medium">
                      <span>Risk Rating: {scanDetail.riskAssessment.risk_rating}</span>
                      <span className="font-mono tabular-nums text-slate-400">
                        {scanDetail.riskAssessment.false_positives_filtered} noise filtered
                      </span>
                    </div>
                    <p className="text-slate-400 leading-relaxed">
                      {scanDetail.riskAssessment.executive_summary}
                    </p>
                  </div>
                )}

                {scanDetail.scan.status === 'completed' && (
                  <div className="flex items-center gap-2.5 pt-1">
                    <button
                      type="button"
                      onClick={handlePdfExport}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                      Download PDF
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadCsvReport(scanDetail.scan.id, scanDetail.scan.website_name)}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" aria-hidden="true" />
                      Export CSV
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Organized Results Section */}
      {scanDetail && (
        <div className="rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
          <div className="p-5 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="font-display text-base font-semibold text-white">
                Scan Results — {scanDetail.scan.website_name}
              </h3>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                {scanDetail.scan.base_url} · {scanDetail.pages.length} page(s) crawled · {scanDetail.vulnerabilities.length} finding(s)
              </p>
            </div>

            <div className="flex items-center gap-1 p-1 bg-[#070B14] border border-slate-800 rounded-lg">
              <button
                type="button"
                onClick={() => setResultTab('findings')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  resultTab === 'findings'
                    ? 'bg-cyan-500/15 text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Detected Vulnerabilities ({scanDetail.vulnerabilities.length})
              </button>
              <button
                type="button"
                onClick={() => setResultTab('pages')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                  resultTab === 'pages'
                    ? 'bg-cyan-500/15 text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Crawled Pages ({scanDetail.pages.length})
              </button>
            </div>
          </div>

          {resultTab === 'findings' ? (
            scanDetail.vulnerabilities.length === 0 ? (
              <div className="p-10 text-center space-y-2">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" aria-hidden="true" />
                <p className="text-sm font-medium text-white">
                  {isRunning ? 'Evaluating crawled endpoints...' : 'Zero Verified Vulnerabilities Detected'}
                </p>
                <p className="text-xs text-slate-400">
                  {isRunning
                    ? 'Findings will appear here once the analysis phase completes.'
                    : 'Security headers, cookie flags, CSRF controls, and input handling passed all checks.'}
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800/80 text-[11px] font-medium text-slate-400 bg-[#090F1D]">
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Vulnerability</th>
                      <th className="py-3 px-4">Category</th>
                      <th className="py-3 px-4">Affected URL</th>
                      <th className="py-3 px-4">OWASP / NIST</th>
                      <th className="py-3 px-4 text-right">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs">
                    {scanDetail.vulnerabilities.map((vuln) => (
                      <tr key={vuln.id} className="hover:bg-slate-800/25 transition-colors">
                        <td className="py-3 px-4">
                          <SeverityText severity={vuln.severity} />
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-medium text-slate-100">{vuln.name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">
                            {vuln.rule_code} {vuln.parameter_name ? `· param: ${vuln.parameter_name}` : ''}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-slate-300">{vuln.category}</td>
                        <td className="py-3 px-4 font-mono text-slate-400 max-w-[240px] truncate">
                          {vuln.affected_url}
                        </td>
                        <td className="py-3 px-4 text-slate-300">
                          <div>{vuln.owasp_top10}</div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            {vuln.owasp_wstg} · {vuln.nist_800_115}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => onSelectVulnerability(vuln)}
                            className="px-3 py-1.5 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/25 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer"
                          >
                            Inspect & Fix
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800/80 text-[11px] font-medium text-slate-400 bg-[#090F1D]">
                    <th className="py-3 px-4">URL</th>
                    <th className="py-3 px-4 text-right">HTTP</th>
                    <th className="py-3 px-4 text-right">Forms</th>
                    <th className="py-3 px-4 text-right">Inputs</th>
                    <th className="py-3 px-4 text-right">Links</th>
                    <th className="py-3 px-4 text-right">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs">
                  {scanDetail.pages.map((page) => (
                    <tr key={page.id} className="hover:bg-slate-800/25 transition-colors">
                      <td className="py-3 px-4 font-mono text-slate-200 max-w-[340px] truncate">
                        {page.url}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-emerald-400">
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                          {page.http_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                        {page.forms_count}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                        {page.inputs_count}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                        {page.links_count}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-400">
                        {page.response_time_ms} ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
