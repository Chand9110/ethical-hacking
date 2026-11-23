import { useEffect, useState } from 'react';
import {
  Activity,
  BookOpen,
  FileBarChart2,
  GitCompare,
  LogOut,
  Menu,
  Plus,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react';
import { AdminGovernanceView } from './components/AdminGovernanceView';
import { AuthGate } from './components/AuthGate';
import { ComparisonView } from './components/ComparisonView';
import { DashboardOverview } from './components/DashboardOverview';
import { RecommendationsLibraryView } from './components/RecommendationsLibraryView';
import { ReportsArchiveView } from './components/ReportsArchiveView';
import { ScanWorkspace } from './components/ScanWorkspace';
import { VulnerabilitiesView } from './components/VulnerabilitiesView';
import { apiFetch, setAuthToken } from './lib/api';
import type { AuthStatus, OverviewResponse, UserProfile, VulnerabilityRecord } from './types';

type NavView =
  | 'overview'
  | 'scanner'
  | 'vulnerabilities'
  | 'comparison'
  | 'reports'
  | 'library'
  | 'governance';

const NAV_LABELS: Record<NavView, string> = {
  overview: 'Security Overview',
  scanner: 'Website Scanner',
  vulnerabilities: 'Vulnerabilities & Remediation',
  comparison: 'Security Comparison',
  reports: 'Reports Archive',
  library: 'Recommendations & Demo Store',
  governance: 'Users & Audit Logs',
};

export default function App() {
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [activeView, setActiveView] = useState<NavView>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);

  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [vulnScanFilter, setVulnScanFilter] = useState<number | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<VulnerabilityRecord | null>(null);

  useEffect(() => {
    apiFetch<AuthStatus>('/api/auth/status')
      .then(setAuthStatus)
      .catch(() => setAuthStatus({ hasUsers: false, hasAdmin: false, envPasscodeConfigured: false }));
  }, []);

  const loadOverview = async () => {
    setOverviewLoading(true);
    try {
      const data = await apiFetch<OverviewResponse>('/api/dashboard/overview');
      setOverview(data);
    } catch {
      // Handled gracefully
    } finally {
      setOverviewLoading(false);
    }
  };

  useEffect(() => {
    if (user) {
      void loadOverview();
    }
  }, [user]);

  const handleSignOut = async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network error on logout
    }
    setAuthToken(null);
    setUser(null);
    setOverview(null);
    const updatedStatus = await apiFetch<AuthStatus>('/api/auth/status').catch(() => null);
    if (updatedStatus) setAuthStatus(updatedStatus);
  };

  if (!authStatus) {
    return (
      <div className="min-h-screen bg-[#070B14] flex items-center justify-center text-xs text-slate-400">
        Initializing security workspace...
      </div>
    );
  }

  if (!user) {
    return (
      <AuthGate
        authStatus={authStatus}
        onAuthenticated={(authedUser) => {
          setUser(authedUser);
          setActiveView('overview');
        }}
      />
    );
  }

  const navItems: { id: NavView; label: string; icon: typeof Activity; adminOnly?: boolean }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'scanner', label: 'Website Scanner', icon: Radar },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'comparison', label: 'Comparison', icon: GitCompare },
    { id: 'reports', label: 'Reports', icon: FileBarChart2 },
    { id: 'library', label: 'Library & Demo', icon: BookOpen },
    { id: 'governance', label: 'Governance', icon: Users, adminOnly: true },
  ];

  const navigateTo = (view: NavView) => {
    setActiveView(view);
    setMobileMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex">
      {/* Mobile Sidebar Backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar Navigation */}
      <aside
        className={`fixed lg:sticky top-0 left-0 z-40 h-screen w-64 shrink-0 bg-[#090F1D] border-r border-slate-800/80 flex flex-col transition-transform duration-200 lg:translate-x-0 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="h-16 px-5 border-b border-slate-800/80 flex items-center justify-between">
          <button
            type="button"
            onClick={() => navigateTo('overview')}
            className="flex items-center gap-2.5 text-left cursor-pointer"
          >
            <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0" aria-hidden="true" />
            <span className="font-display text-base font-semibold tracking-tight text-white whitespace-nowrap">
              AegisCommerce
            </span>
          </button>
          <button
            type="button"
            onClick={() => setMobileMenuOpen(false)}
            className="lg:hidden p-1.5 text-slate-400 hover:text-white cursor-pointer"
            aria-label="Close navigation menu"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <nav className="flex-1 p-3.5 space-y-1 overflow-y-auto" aria-label="Primary Sidebar Navigation">
          {navItems
            .filter((item) => !item.adminOnly || user.role === 'admin')
            .map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigateTo(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                    isActive
                      ? 'bg-cyan-500/12 text-cyan-300 border border-cyan-500/25'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40 border border-transparent'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  {item.label}
                </button>
              );
            })}
        </nav>

        {/* User Account Footer */}
        <div className="p-4 border-t border-slate-800/80 space-y-3">
          <div className="text-xs">
            <p className="font-medium text-slate-200 truncate">{user.name}</p>
            <p className="text-[11px] text-slate-400 truncate">
              {user.email} · <span className="capitalize text-cyan-400">{user.role}</span>
            </p>
          </div>
          <button
            type="button"
            onClick={() => void handleSignOut()}
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-[#0D1424] hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 transition-colors whitespace-nowrap cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Bar */}
        <header className="h-16 px-5 lg:px-8 border-b border-slate-800/80 bg-[#070B14]/95 sticky top-0 z-20 flex items-center justify-between gap-6">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg bg-[#0D1424] border border-slate-800 text-slate-300 hover:text-white cursor-pointer"
              aria-label="Open navigation menu"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-xs text-slate-400 min-w-0">
              <span className="hidden sm:inline whitespace-nowrap">Platform</span>
              <span className="hidden sm:inline" aria-hidden="true">/</span>
              <h1 className="font-display text-sm sm:text-base font-semibold text-white truncate">
                {NAV_LABELS[activeView]}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => navigateTo('scanner')}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-colors whitespace-nowrap cursor-pointer"
            >
              <Plus className="w-4 h-4" aria-hidden="true" />
              New Scan
            </button>
          </div>
        </header>

        {/* Viewport Container */}
        <main className="flex-1 p-5 lg:p-8 max-w-[1440px] w-full mx-auto">
          {activeView === 'overview' && (
            <DashboardOverview
              overview={overview}
              loading={overviewLoading}
              userRole={user.role}
              onRefresh={() => void loadOverview()}
              onNavigateToScan={(scanId) => {
                if (scanId) setActiveScanId(scanId);
                setActiveView('scanner');
              }}
              onInspectScanVulnerabilities={(scanId) => {
                setVulnScanFilter(scanId);
                setSelectedVulnerability(null);
                setActiveView('vulnerabilities');
              }}
            />
          )}

          {activeView === 'scanner' && (
            <ScanWorkspace
              activeScanId={activeScanId}
              userRole={user.role}
              onScanStarted={(scanId) => {
                setActiveScanId(scanId);
              }}
              onScanFinished={() => {
                void loadOverview();
              }}
              onSelectVulnerability={(vuln) => {
                setVulnScanFilter(vuln.scan_id);
                setSelectedVulnerability(vuln);
                setActiveView('vulnerabilities');
              }}
            />
          )}

          {activeView === 'vulnerabilities' && (
            <VulnerabilitiesView
              initialScanIdFilter={vulnScanFilter}
              selectedVulnerability={selectedVulnerability}
              userRole={user.role}
              onSelectVulnerability={setSelectedVulnerability}
              onStatusUpdated={() => void loadOverview()}
              onClearScanFilter={() => setVulnScanFilter(null)}
            />
          )}

          {activeView === 'comparison' && <ComparisonView />}

          {activeView === 'reports' && <ReportsArchiveView />}

          {activeView === 'library' && <RecommendationsLibraryView userRole={user.role} />}

          {activeView === 'governance' && user.role === 'admin' && (
            <AdminGovernanceView currentUserId={user.id} />
          )}
        </main>
      </div>
    </div>
  );
}
