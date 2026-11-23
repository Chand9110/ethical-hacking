import { useEffect, useMemo, useState } from 'react';
import { BookOpen, Code2, Globe, Search } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { RecommendationLibraryItem, UserRole } from '../types';
import { SeverityText } from './SeverityIndicator';

interface DemoPageSnapshot {
  path: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  htmlPreview: string;
}

interface DemoStorePayload {
  url: string;
  name: string;
  posture: 'vulnerable' | 'hardened';
  pages: DemoPageSnapshot[];
}

export function RecommendationsLibraryView({ userRole }: { userRole: UserRole }) {
  const [tab, setTab] = useState<'library' | 'demo'>('library');
  const [items, setItems] = useState<RecommendationLibraryItem[]>([]);
  const [search, setSearch] = useState('');
  const [demoData, setDemoData] = useState<DemoStorePayload | null>(null);
  const [selectedPath, setSelectedPath] = useState('/');
  const [loading, setLoading] = useState(true);

  const canMutate = userRole === 'admin' || userRole === 'analyst';

  const loadAll = async () => {
    setLoading(true);
    try {
      const [recRes, demoRes] = await Promise.all([
        apiFetch<{ recommendations: RecommendationLibraryItem[] }>('/api/recommendations'),
        apiFetch<DemoStorePayload>('/api/demo-store'),
      ]);
      setItems(recRes.recommendations);
      setDemoData(demoRes);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  const filteredItems = useMemo(() => {
    if (!search.trim()) return items;
    const q = search.toLowerCase();
    return items.filter(
      (i) =>
        i.title.toLowerCase().includes(q) ||
        i.rule_code.toLowerCase().includes(q) ||
        i.owasp_top10.toLowerCase().includes(q) ||
        i.category.toLowerCase().includes(q)
    );
  }, [items, search]);

  const handleSwitchPosture = async (posture: 'vulnerable' | 'hardened') => {
    await apiFetch('/api/demo-store/posture', {
      method: 'POST',
      body: JSON.stringify({ posture }),
    });
    const refreshed = await apiFetch<DemoStorePayload>('/api/demo-store');
    setDemoData(refreshed);
  };

  const activePage = demoData?.pages.find((p) => p.path === selectedPath) ?? demoData?.pages[0];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-1 p-1 bg-[#0D1424] border border-slate-800 rounded-lg w-fit">
          <button
            type="button"
            onClick={() => setTab('library')}
            className={`inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
              tab === 'library' ? 'bg-cyan-500/15 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" aria-hidden="true" />
            Security Recommendations Library
          </button>
          <button
            type="button"
            onClick={() => setTab('demo')}
            className={`inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
              tab === 'demo' ? 'bg-cyan-500/15 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" aria-hidden="true" />
            Demo E-Commerce Storefront Inspector
          </button>
        </div>

        {tab === 'library' && (
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search rule, OWASP, or control..."
              className="w-full pl-8 pr-3 py-2 text-xs bg-[#0D1424] border border-slate-800 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        )}
      </div>

      {loading ? (
        <div className="h-64 rounded-xl bg-[#0D1424] border border-slate-800/80 animate-pulse" />
      ) : tab === 'library' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {filteredItems.map((rule) => (
            <article
              key={rule.rule_code}
              className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-3.5"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400 mb-1">
                    <SeverityText severity={rule.default_severity} />
                    <span aria-hidden="true">·</span>
                    <span className="font-mono text-cyan-300">{rule.rule_code}</span>
                    <span aria-hidden="true">·</span>
                    <span>{rule.category}</span>
                  </div>
                  <h3 className="font-display text-base font-semibold text-white">{rule.title}</h3>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400">
                <span>{rule.owasp_top10}</span>
                <span aria-hidden="true">·</span>
                <span>{rule.owasp_wstg}</span>
                <span aria-hidden="true">·</span>
                <span>{rule.owasp_asvs}</span>
                <span aria-hidden="true">·</span>
                <span>{rule.nist_800_115}</span>
              </div>

              <div className="text-xs text-slate-300 whitespace-pre-line leading-relaxed">
                {rule.remediation_steps}
              </div>

              <div className="p-3 rounded-lg bg-[#070B14] border border-slate-800/80 text-xs text-slate-400">
                <span className="text-slate-200 font-medium">Preventive Control: </span>
                {rule.preventive_measures}
              </div>

              <div>
                <div className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400 mb-1">
                  <Code2 className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
                  Reference Pattern
                </div>
                <pre className="p-3 rounded-lg bg-[#070B14] border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto">
                  {rule.code_example}
                </pre>
              </div>
            </article>
          ))}
        </div>
      ) : (
        demoData && (
          <div className="space-y-5">
            <div className="p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="font-display text-base font-semibold text-white">
                  {demoData.name} — Sandboxed Evaluation Storefront
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">{demoData.url}</p>
              </div>

              <div className="flex items-center gap-1 p-1 bg-[#070B14] border border-slate-800 rounded-lg">
                <button
                  type="button"
                  disabled={!canMutate}
                  onClick={() => void handleSwitchPosture('vulnerable')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                    demoData.posture === 'vulnerable'
                      ? 'bg-rose-500/15 text-rose-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Vulnerable Baseline
                </button>
                <button
                  type="button"
                  disabled={!canMutate}
                  onClick={() => void handleSwitchPosture('hardened')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                    demoData.posture === 'hardened'
                      ? 'bg-emerald-500/15 text-emerald-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Hardened / Patched
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
              <div className="lg:col-span-4 rounded-xl bg-[#0D1424] border border-slate-800/80 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800/80 bg-[#090F1D] text-xs font-medium text-slate-300">
                  Simulated Storefront Routes
                </div>
                <div className="divide-y divide-slate-800/60">
                  {demoData.pages.map((p) => (
                    <button
                      key={p.path}
                      type="button"
                      onClick={() => setSelectedPath(p.path)}
                      className={`w-full text-left px-4 py-3 text-xs font-mono transition-colors cursor-pointer ${
                        activePage?.path === p.path
                          ? 'bg-cyan-500/10 text-cyan-300'
                          : 'text-slate-300 hover:bg-slate-800/30'
                      }`}
                    >
                      {p.path}
                    </button>
                  ))}
                </div>
              </div>

              {activePage && (
                <div className="lg:col-span-8 p-5 rounded-xl bg-[#0D1424] border border-slate-800/80 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-cyan-300">{activePage.url}</span>
                    <span className="text-xs font-mono text-slate-400">HTTP {activePage.status}</span>
                  </div>

                  <div>
                    <p className="text-xs font-medium text-slate-300 mb-1.5">HTTP Response Headers & Cookies</p>
                    <pre className="p-3.5 rounded-lg bg-[#070B14] border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                      {JSON.stringify(
                        { headers: activePage.headers, setCookies: activePage.setCookies },
                        null,
                        2
                      )}
                    </pre>
                  </div>

                  <div>
                    <p className="text-xs font-medium text-slate-300 mb-1.5">Rendered HTML Source</p>
                    <pre className="p-3.5 rounded-lg bg-[#070B14] border border-slate-800 text-[11px] font-mono text-slate-400 overflow-x-auto max-h-64">
                      {activePage.htmlPreview}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        )
      )}
    </div>
  );
}
