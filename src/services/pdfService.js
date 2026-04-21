/**
 * pdfService.js — Generates downloadable PDF forensic reports using PDFKit.
 */
const PDFDocument = require('pdfkit');

const COLORS = {
    primary:  '#8b5cf6',
    dark:     '#1a1a2e',
    critical: '#ff3b30',
    high:     '#ff9500',
    medium:   '#e6b800',
    low:      '#30d158',
    text:     '#2d3748',
    muted:    '#718096',
    white:    '#ffffff',
    border:   '#e2e8f0',
    bg:       '#f7fafc',
};

const LEFT = 50;

function severityColor(sev) {
    return COLORS[sev?.toLowerCase()] || COLORS.muted;
}

function resetX(doc) {
    doc.x = LEFT;
}

/**
 * Generates a PDF report buffer for a completed scan.
 */
function generatePDFReport(scan, findings, aiReport) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: LEFT, size: 'A4' });
        const chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end',  () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        const pageWidth = doc.page.width - LEFT * 2; // 495pt for A4

        // ─── HEADER ─────────────────────────────────────────────
        doc.rect(0, 0, doc.page.width, 80).fill(COLORS.dark);

        doc.fill(COLORS.primary).fontSize(22).font('Helvetica-Bold')
           .text('HeapTruffle', LEFT, 22);
        doc.fill(COLORS.white).fontSize(9).font('Helvetica')
           .text('AI-Assisted Browser Memory Forensics Platform', LEFT, 50);
        doc.fill(COLORS.white).fontSize(9).font('Helvetica-Bold')
           .text('CONFIDENTIAL — SECURITY REPORT', LEFT, 28, { align: 'right', width: pageWidth });

        doc.y = 98; resetX(doc);

        // ─── TITLE ───────────────────────────────────────────────
        doc.fill(COLORS.text).fontSize(18).font('Helvetica-Bold')
           .text('Forensic Scan Report', LEFT, doc.y, { width: pageWidth, align: 'center' });
        doc.moveDown(0.35); resetX(doc);

        doc.fill(COLORS.muted).fontSize(10).font('Helvetica')
           .text(`Target: ${scan.target_url}`, LEFT, doc.y, { width: pageWidth, align: 'center' });
        doc.moveDown(0.2); resetX(doc);

        doc.fill(COLORS.muted).fontSize(10)
           .text(`Generated: ${new Date().toUTCString()}`, LEFT, doc.y, { width: pageWidth, align: 'center' });

        doc.moveDown(1.2); resetX(doc);
        rule(doc, pageWidth);
        doc.moveDown(0.8); resetX(doc);

        // ─── SCAN METADATA ───────────────────────────────────────
        sectionTitle(doc, '1. Scan Metadata', pageWidth);
        infoTable(doc, [
            ['Scan ID',        scan.id],
            ['Target URL',     scan.target_url],
            ['Domain',         scan.domain],
            ['Status',         scan.status?.toUpperCase()],
            ['Initiated',      scan.created_at],
            ['Completed',      scan.completed_at || 'N/A'],
            ['Total Findings', String(findings.length)],
        ], pageWidth);
        doc.moveDown(1.2); resetX(doc);

        // ─── SEVERITY SUMMARY ────────────────────────────────────
        sectionTitle(doc, '2. Severity Distribution', pageWidth);
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        findings.forEach(f => {
            const s = (f.severity || 'low').toLowerCase();
            if (counts[s] !== undefined) counts[s]++;
        });
        const totalScore = findings.length
            ? Math.round(findings.reduce((s, f) => s + (f.score || 0), 0) / findings.length)
            : 0;
        drawSeverityBox(doc, counts, totalScore, pageWidth);
        doc.moveDown(1.2); resetX(doc);

        // ─── AI EXECUTIVE SUMMARY ────────────────────────────────
        if (aiReport) {
            sectionTitle(doc, '3. AI Security Intelligence Summary', pageWidth);
            renderAIReport(doc, aiReport, pageWidth);
            doc.moveDown(1.2); resetX(doc);
        }

        // ─── DETAILED FINDINGS ───────────────────────────────────
        sectionTitle(doc, `${aiReport ? '4' : '3'}. Detailed Findings (${findings.length})`, pageWidth);
        doc.moveDown(0.4); resetX(doc);

        findings.slice(0, 40).forEach((f, i) => {
            if (doc.y > doc.page.height - 180) { doc.addPage(); resetX(doc); }
            findingBlock(doc, f, i + 1, pageWidth);
        });

        if (findings.length > 40) {
            doc.moveDown(0.5); resetX(doc);
            doc.fill(COLORS.muted).fontSize(9).font('Helvetica-Oblique')
               .text(
                   `... and ${findings.length - 40} more findings. View the full list in the platform dashboard.`,
                   LEFT, doc.y, { width: pageWidth }
               );
        }

        doc.moveDown(1.5); resetX(doc);

        // ─── RECOMMENDATIONS ─────────────────────────────────────
        sectionTitle(doc, `${aiReport ? '5' : '4'}. Top Recommendations`, pageWidth);
        doc.moveDown(0.4); resetX(doc);

        const critHigh = findings
            .filter(f => ['critical', 'high'].includes(f.severity?.toLowerCase()))
            .slice(0, 8);

        if (critHigh.length === 0) {
            doc.fill(COLORS.muted).fontSize(10).font('Helvetica')
               .text('No critical or high severity findings. Maintain regular forensic scans.', LEFT, doc.y, { width: pageWidth });
        } else {
            critHigh.forEach((f, i) => {
                resetX(doc);
                doc.fill(COLORS.text).fontSize(10).font('Helvetica-Bold')
                   .text(`${i + 1}. ${f.artifact_type?.replace(/_/g, ' ').toUpperCase()}`, LEFT, doc.y, { width: pageWidth });
                resetX(doc);
                doc.fill(COLORS.muted).fontSize(9).font('Helvetica')
                   .text(f.recommendation || 'Review and remediate.', LEFT, doc.y, { width: pageWidth, indent: 14 });
                doc.moveDown(0.4); resetX(doc);
            });
        }

        // ─── FOOTER ──────────────────────────────────────────────
        doc.moveDown(2); resetX(doc);
        rule(doc, pageWidth);
        doc.moveDown(0.4); resetX(doc);
        doc.fill(COLORS.muted).fontSize(8).font('Helvetica')
           .text(
               'This report was generated automatically by HeapTruffle v2.0 — AI-Assisted Browser Memory Forensics Platform.',
               LEFT, doc.y, { width: pageWidth, align: 'center' }
           );
        resetX(doc);
        doc.text('For internal use only. Unauthorized disclosure is prohibited.',
            LEFT, doc.y, { width: pageWidth, align: 'center' });

        doc.end();
    });
}

// ─── AI Report Renderer ──────────────────────────────────────────────────────
/**
 * Parses AI report markdown line-by-line and renders:
 *   - ## headings → purple bold
 *   - **bold-only lines** → purple bold (fallback heading style)
 *   - - bullets → indented bullet points, no extra gaps
 *   - blank lines  → tiny gap (not a full blank line)
 *   - regular text → normal body
 */
function renderAIReport(doc, aiReport, pageWidth) {
    const lines = aiReport.replace(/\r\n/g, '\n').split('\n');
    let prevWasBlank = false;

    lines.forEach(rawLine => {
        const line = rawLine.trim();

        // ── Blank line ───────────────────────────────────────────
        if (!line) {
            if (!prevWasBlank) {
                // Only one small gap — never stack multiple blank lines
                doc.moveDown(0.15);
                resetX(doc);
            }
            prevWasBlank = true;
            return;
        }
        prevWasBlank = false;

        // ── Markdown heading: ## Title ───────────────────────────
        const headingMatch = line.match(/^#{1,6}\s+(.*)/);
        if (headingMatch) {
            const title = headingMatch[1].replace(/\*\*/g, '').replace(/\*/g, '').trim();
            doc.moveDown(0.3); resetX(doc);
            doc.fill(COLORS.primary).fontSize(10).font('Helvetica-Bold')
               .text(title, LEFT, doc.y, { width: pageWidth });
            resetX(doc);
            return;
        }

        // ── Bold-only line acting as heading: **Title** ──────────
        // e.g. "**Executive Summary**" or "**Risk Assessment**:"
        if (/^\*\*[^*]+\*\*[:.]*$/.test(line)) {
            const title = line.replace(/\*\*/g, '').replace(/[:.]+$/, '').trim();
            doc.moveDown(0.3); resetX(doc);
            doc.fill(COLORS.primary).fontSize(10).font('Helvetica-Bold')
               .text(title, LEFT, doc.y, { width: pageWidth });
            resetX(doc);
            return;
        }

        // ── Bullet item: - text  or  * text ─────────────────────
        const bulletMatch = line.match(/^[-*•]\s+(.*)/);
        if (bulletMatch) {
            const content = bulletMatch[1]
                .replace(/\*\*/g, '').replace(/\*/g, '').replace(/`/g, '').trim();
            resetX(doc);
            doc.fill(COLORS.text).fontSize(9).font('Helvetica')
               .text(`• ${content}`, LEFT + 8, doc.y, { width: pageWidth - 8, lineGap: 1 });
            resetX(doc);
            return;
        }

        // ── Regular body text ────────────────────────────────────
        const cleanLine = line.replace(/\*\*/g, '').replace(/\*/g, '').replace(/`/g, '').trim();
        resetX(doc);
        doc.fill(COLORS.text).fontSize(9.5).font('Helvetica')
           .text(cleanLine, LEFT, doc.y, { width: pageWidth, lineGap: 1.5 });
        resetX(doc);
    });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function sectionTitle(doc, title, width) {
    doc.fill(COLORS.primary).fontSize(13).font('Helvetica-Bold')
       .text(title, LEFT, doc.y, { width });
    doc.moveDown(0.45);
    doc.x = LEFT;
}

function rule(doc, width) {
    doc.moveTo(LEFT, doc.y)
       .lineTo(LEFT + width, doc.y)
       .strokeColor(COLORS.border).lineWidth(1).stroke();
}

function infoTable(doc, rows, width) {
    rows.forEach(([key, val]) => {
        const y = doc.y;
        doc.fill(COLORS.muted).fontSize(9.5).font('Helvetica-Bold')
           .text(key + ':', LEFT, y, { width: 120 });
        doc.fill(COLORS.text).fontSize(9.5).font('Helvetica')
           .text(String(val || ''), LEFT + 125, y, { width: width - 125 });
        doc.moveDown(0.4);
        doc.x = LEFT;
    });
}

function drawSeverityBox(doc, counts, score, width) {
    const gap  = 10;
    const boxW = (width - gap * 3) / 4;
    const severities = [
        { label: 'CRITICAL', key: 'critical', color: COLORS.critical },
        { label: 'HIGH',     key: 'high',     color: COLORS.high     },
        { label: 'MEDIUM',   key: 'medium',   color: COLORS.medium   },
        { label: 'LOW',      key: 'low',       color: COLORS.low      },
    ];

    let x = LEFT;
    const boxY = doc.y;

    severities.forEach(s => {
        doc.roundedRect(x, boxY, boxW, 52, 6).fillAndStroke(COLORS.bg, COLORS.border);
        doc.fill(s.color).fontSize(21).font('Helvetica-Bold')
           .text(String(counts[s.key]), x, boxY + 8, { width: boxW, align: 'center' });
        doc.fill(COLORS.muted).fontSize(7.5).font('Helvetica-Bold')
           .text(s.label, x, boxY + 36, { width: boxW, align: 'center' });
        x += boxW + gap;
    });

    doc.y  = boxY + 60;
    doc.x  = LEFT;
    doc.fill(COLORS.muted).fontSize(8.5).font('Helvetica')
       .text(`Overall Risk Score: ${score}/100`, LEFT, doc.y, { width, align: 'right' });
    doc.x = LEFT;
}

function findingBlock(doc, f, index, width) {
    const sev    = (f.severity || 'low').toLowerCase();
    const col    = severityColor(sev);
    const startY = doc.y;

    doc.rect(LEFT, startY, 4, 48).fill(col);

    doc.fill(COLORS.text).fontSize(9.5).font('Helvetica-Bold')
       .text(
           `#${index} — ${(f.artifact_type || '').replace(/_/g, ' ').toUpperCase()}`,
           LEFT + 10, startY + 3, { width: width - 14 }
       );

    doc.fill(col).fontSize(8).font('Helvetica-Bold')
       .text(
           `[${sev.toUpperCase()}]  Score: ${f.score || 0}  Confidence: ${f.confidence || '?'}%`,
           LEFT + 10, startY + 17, { width: width - 14 }
       );

    const rawVal = String(f.raw_value || '');
    doc.fill(COLORS.muted).fontSize(8).font('Helvetica')
       .text(
           `Value: ${rawVal.slice(0, 80)}${rawVal.length > 80 ? '...' : ''}`,
           LEFT + 10, startY + 30, { width: width - 14 }
       );

    doc.y = startY + 54;
    doc.x = LEFT;
}

module.exports = { generatePDFReport };
