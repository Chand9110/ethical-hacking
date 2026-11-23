import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { RiskAssessmentRecord, ScanRecord, VulnerabilityRecord } from '../types';

export interface PdfReportPayload {
  reportTitle: string;
  scan: ScanRecord;
  riskAssessment: RiskAssessmentRecord | null;
  vulnerabilities: VulnerabilityRecord[];
}

export function generatePdfSecurityReport(payload: PdfReportPayload): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const { reportTitle, scan, riskAssessment, vulnerabilities } = payload;

  // Header band
  doc.setFillColor(7, 11, 20);
  doc.rect(0, 0, 210, 34, 'F');

  doc.setTextColor(34, 211, 238);
  doc.setFontSize(10);
  doc.text('AEGISCOMMERCE SECURITY ASSESSMENT REPORT', 14, 12);

  doc.setTextColor(248, 250, 252);
  doc.setFontSize(16);
  doc.text(reportTitle.slice(0, 62), 14, 21);

  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text(
    `Target: ${scan.base_url}  |  Scan #${scan.id}  |  Generated: ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
    14,
    28
  );

  // Score & Executive Summary
  let y = 44;
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(12);
  doc.text('1. Executive Risk Summary', 14, y);
  y += 6;

  const score = riskAssessment?.overall_score ?? scan.security_score ?? 0;
  const rating = riskAssessment?.risk_rating ?? 'Pending';
  const filteredFp = riskAssessment?.false_positives_filtered ?? 0;

  autoTable(doc, {
    startY: y,
    head: [['Security Score', 'Risk Rating', 'Pages Crawled', 'Verified Findings', 'False Positives Filtered']],
    body: [[
      `${score} / 100`,
      rating,
      String(scan.pages_scanned),
      String(vulnerabilities.length),
      String(filteredFp),
    ]],
    theme: 'grid',
    headStyles: { fillColor: [13, 20, 36], textColor: [34, 211, 238], fontSize: 9 },
    bodyStyles: { fontSize: 10, textColor: [15, 23, 42] },
    margin: { left: 14, right: 14 },
  });

  const afterKpiY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85);
  const summaryText = riskAssessment?.executive_summary || 'Automated non-destructive e-commerce security assessment.';
  const wrappedSummary = doc.splitTextToSize(summaryText, 182);
  doc.text(wrappedSummary, 14, afterKpiY);

  let nextY = afterKpiY + wrappedSummary.length * 5 + 6;

  // Severity Breakdown Table
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const v of vulnerabilities) {
    if (v.severity in counts) counts[v.severity] += 1;
  }

  doc.setTextColor(15, 23, 42);
  doc.setFontSize(12);
  doc.text('2. Severity & Standards Summary', 14, nextY);
  nextY += 5;

  autoTable(doc, {
    startY: nextY,
    head: [['Critical', 'High', 'Medium', 'Low', 'Applicable Security Standards']],
    body: [[
      String(counts.Critical),
      String(counts.High),
      String(counts.Medium),
      String(counts.Low),
      'OWASP Top 10 (2021), OWASP WSTG, OWASP ASVS v4.0, NIST SP 800-115',
    ]],
    theme: 'grid',
    headStyles: { fillColor: [13, 20, 36], textColor: [248, 250, 252], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: 14, right: 14 },
  });

  nextY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

  // Detailed Findings Table
  doc.setTextColor(15, 23, 42);
  doc.setFontSize(12);
  doc.text('3. Detected Vulnerabilities & Recommendations', 14, nextY);
  nextY += 4;

  if (vulnerabilities.length === 0) {
    doc.setFontSize(10);
    doc.setTextColor(22, 163, 74);
    doc.text('No vulnerabilities were detected during this scan.', 14, nextY + 6);
  } else {
    autoTable(doc, {
      startY: nextY,
      head: [['Severity', 'Vulnerability', 'Affected URL', 'Standards', 'Evidence & Fix']],
      body: vulnerabilities.map((v) => [
        v.severity,
        `${v.name}\n(${v.rule_code} · ${v.remediation_status})`,
        v.affected_url,
        `${v.owasp_top10}\n${v.owasp_wstg} · ${v.owasp_asvs}\n${v.nist_800_115}`,
        `Evidence: ${v.evidence}\n\nFix: ${v.remediation_steps || v.rec_title || ''}`,
      ]),
      theme: 'striped',
      headStyles: { fillColor: [13, 20, 36], textColor: [34, 211, 238], fontSize: 8.5 },
      bodyStyles: { fontSize: 8, cellPadding: 2.5, textColor: [15, 23, 42] },
      columnStyles: {
        0: { cellWidth: 18, fontStyle: 'bold' },
        1: { cellWidth: 38 },
        2: { cellWidth: 34 },
        3: { cellWidth: 34 },
        4: { cellWidth: 58 },
      },
      margin: { left: 14, right: 14 },
    });
  }

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i += 1) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(
      `AegisCommerce Security Suite · Confidential Assessment · Page ${i} of ${pageCount}`,
      14,
      290
    );
  }

  const slug = scan.website_name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  doc.save(`aegis-report-${slug}-scan-${scan.id}.pdf`);
}
