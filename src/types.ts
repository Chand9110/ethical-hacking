export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface UserProfile {
  id: number;
  name: string;
  email: string;
  role: UserRole;
  created_at: string;
  last_login_at: string | null;
}

export interface AuthStatus {
  hasUsers: boolean;
  hasAdmin: boolean;
  envPasscodeConfigured: boolean;
}

export interface WebsiteRecord {
  id: number;
  name: string;
  base_url: string;
  domain: string;
  authorization_confirmed: number;
  is_demo_target: number;
  created_at: string;
  total_scans?: number;
  latest_score?: number | null;
  latest_scan_id?: number | null;
  last_scanned_at?: string | null;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'stopped' | 'failed';
export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type RemediationStatus = 'Open' | 'In Progress' | 'Resolved' | 'Accepted Risk';

export interface ScanRecord {
  id: number;
  website_id: number;
  website_name: string;
  base_url: string;
  domain: string;
  is_demo_target: number;
  status: ScanStatus;
  scan_mode: 'quick' | 'standard' | 'comprehensive';
  max_pages: number;
  check_sqli: number;
  check_xss: number;
  check_headers: number;
  check_cookies: number;
  check_misconfig: number;
  pages_scanned: number;
  vulnerabilities_found: number;
  security_score: number | null;
  current_url: string;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  risk_rating?: string | null;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  false_positives_filtered?: number;
}

export interface ScannedPageRecord {
  id: number;
  scan_id: number;
  url: string;
  http_status: number;
  content_type: string;
  response_time_ms: number;
  forms_count: number;
  inputs_count: number;
  links_count: number;
  headers_json: string;
  cookies_json: string;
  scanned_at: string;
}

export interface VulnerabilityRecord {
  id: number;
  scan_id: number;
  page_id: number | null;
  website_id: number;
  website_name?: string;
  base_url?: string;
  rule_code: string;
  name: string;
  category: string;
  affected_url: string;
  parameter_name: string;
  severity: SeverityLevel;
  confidence: 'High' | 'Medium' | 'Low';
  description: string;
  evidence: string;
  potential_impact: string;
  owasp_top10: string;
  owasp_wstg: string;
  owasp_asvs: string;
  nist_800_115: string;
  remediation_status: RemediationStatus;
  detected_at: string;
  rec_title?: string;
  remediation_steps?: string;
  preventive_measures?: string;
  secure_coding_practice?: string;
  code_example?: string;
  rec_priority?: string;
}

export interface RiskAssessmentRecord {
  id: number;
  scan_id: number;
  website_id: number;
  overall_score: number;
  risk_rating: 'Critical' | 'High' | 'Moderate' | 'Low';
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  false_positives_filtered: number;
  executive_summary: string;
  threat_actors_summary: string;
  assessed_at: string;
}

export interface OverviewResponse {
  metrics: {
    totalWebsitesScanned: number;
    totalVulnerabilitiesDetected: number;
    activeVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    overallSecurityScore: number;
  };
  owaspBreakdown: { category: string; count: number }[];
  trendHistory: {
    id: number;
    website_name: string;
    started_at: string;
    security_score: number | null;
    vulnerabilities_found: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
  }[];
  recentScans: ScanRecord[];
}

export interface RecommendationLibraryItem {
  rule_code: string;
  title: string;
  category: string;
  default_severity: SeverityLevel;
  owasp_top10: string;
  owasp_wstg: string;
  owasp_asvs: string;
  nist_800_115: string;
  remediation_steps: string;
  preventive_measures: string;
  secure_coding_practice: string;
  code_example: string;
  priority: string;
}

export interface GeneratedReportRecord {
  id: number;
  scan_id: number;
  website_id: number;
  website_name: string;
  base_url: string;
  generated_by_name: string | null;
  report_title: string;
  format: 'PDF' | 'CSV';
  vulnerability_count: number;
  security_score: number;
  generated_at: string;
}

export interface AuditLogRecord {
  id: number;
  user_id: number | null;
  user_email: string | null;
  action: string;
  target: string | null;
  details: string | null;
  ip_address: string | null;
  created_at: string;
}
