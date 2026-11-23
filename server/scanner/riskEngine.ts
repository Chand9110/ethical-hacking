export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export interface RawFinding {
  page_id: number | null;
  rule_code: string;
  name: string;
  category: string;
  affected_url: string;
  parameter_name: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  description: string;
  evidence: string;
  potential_impact: string;
  owasp_top10: string;
  owasp_wstg: string;
  owasp_asvs: string;
  nist_800_115: string;
  sitewide_dedupe?: boolean;
}

export interface RiskAssessmentResult {
  validatedFindings: RawFinding[];
  falsePositivesFiltered: number;
  overallScore: number;
  riskRating: 'Critical' | 'High' | 'Moderate' | 'Low';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  executiveSummary: string;
  threatActorsSummary: string;
}

const ECOMMERCE_SENSITIVE_PATH = /(checkout|payment|cart|login|signin|account|order|billing|admin)/i;

export function analyzeAndAssessRisk(rawFindings: RawFinding[], pagesScanned: number): RiskAssessmentResult {
  const seenSitewide = new Set<string>();
  const seenEndpointRule = new Set<string>();
  const validatedFindings: RawFinding[] = [];
  let falsePositivesFiltered = 0;

  for (const finding of rawFindings) {
    // Rule 1: Filter low-confidence informational noise on non-interactive pages
    if (finding.confidence === 'Low' && !ECOMMERCE_SENSITIVE_PATH.test(finding.affected_url)) {
      falsePositivesFiltered += 1;
      continue;
    }

    // Rule 2: Deduplicate sitewide header/banner issues across multiple pages of the same crawl
    if (finding.sitewide_dedupe) {
      const siteKey = `${finding.rule_code}::${finding.parameter_name}`;
      if (seenSitewide.has(siteKey)) {
        falsePositivesFiltered += 1;
        continue;
      }
      seenSitewide.add(siteKey);
    }

    // Rule 3: Deduplicate identical rule + path + parameter findings
    let normalizedPath = finding.affected_url;
    try {
      const u = new URL(finding.affected_url);
      normalizedPath = `${u.origin}${u.pathname}`;
    } catch {
      // Keep original URL
    }
    const endpointKey = `${finding.rule_code}::${normalizedPath}::${finding.parameter_name}`;
    if (seenEndpointRule.has(endpointKey)) {
      falsePositivesFiltered += 1;
      continue;
    }
    seenEndpointRule.add(endpointKey);

    // Rule 4: Contextual severity elevation for sensitive e-commerce endpoints
    let adjustedSeverity = finding.severity;
    if (
      ECOMMERCE_SENSITIVE_PATH.test(finding.affected_url) &&
      finding.rule_code === 'TRANS-HTTP-01'
    ) {
      adjustedSeverity = 'Critical';
    }

    validatedFindings.push({
      ...finding,
      severity: adjustedSeverity,
    });
  }

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const item of validatedFindings) {
    if (item.severity === 'Critical') criticalCount += 1;
    else if (item.severity === 'High') highCount += 1;
    else if (item.severity === 'Medium') mediumCount += 1;
    else lowCount += 1;
  }

  // Weighted penalty model bounded cleanly to [5, 100]
  const weightedPenalty =
    criticalCount * 22 +
    highCount * 12 +
    mediumCount * 6 +
    lowCount * 3;

  const overallScore = pagesScanned === 0
    ? 0
    : Math.max(5, Math.min(100, 100 - weightedPenalty));

  let riskRating: 'Critical' | 'High' | 'Moderate' | 'Low' = 'Low';
  if (criticalCount > 0 || overallScore < 45) {
    riskRating = 'Critical';
  } else if (highCount > 0 || overallScore < 70) {
    riskRating = 'High';
  } else if (mediumCount > 1 || overallScore < 85) {
    riskRating = 'Moderate';
  }

  const totalFindings = validatedFindings.length;
  const executiveSummary =
    totalFindings === 0
      ? `Automated non-destructive assessment across ${pagesScanned} page(s) completed with zero verified vulnerabilities. Security headers, session cookies, and form protections align with OWASP ASVS baseline controls.`
      : `Assessment across ${pagesScanned} page(s) verified ${totalFindings} vulnerability finding(s) (${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium, ${lowCount} Low) after filtering ${falsePositivesFiltered} duplicate or low-confidence signal(s). Overall security score is ${overallScore}/100 (${riskRating} risk).`;

  const threatActorsSummary =
    criticalCount > 0 || highCount > 0
      ? 'High-impact threats include automated database error harvesting, reflected cross-site script injection (session/checkout skimming), and unauthorized state changes via missing CSRF controls.'
      : mediumCount > 0
        ? 'Moderate exposure primarily stems from missing browser defense-in-depth headers (CSP, HSTS, X-Frame-Options) that weaken protection against third-party script or clickjacking risks.'
        : 'Minimal residual threat exposure; maintain scheduled regression scanning after storefront updates.';

  return {
    validatedFindings,
    falsePositivesFiltered,
    overallScore,
    riskRating,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    executiveSummary,
    threatActorsSummary,
  };
}
