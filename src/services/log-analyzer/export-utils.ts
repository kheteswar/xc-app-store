import type { HookData } from 'jspdf-autotable';
import type { AccessLogEntry } from '../rate-limit-advisor/types';
import type { BreakdownResult } from './types';

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeCSV(v: unknown): string {
  const s = v === undefined || v === null ? '' : String(v);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

// ═══════════════════════════════════════════════════════════════════
// RAW LOG EXPORTS
// ═══════════════════════════════════════════════════════════════════

export function exportAsJSON(logs: AccessLogEntry[], filename: string = 'log-analysis.json'): void {
  const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
  triggerDownload(blob, filename);
}

export function exportAsCSV(logs: AccessLogEntry[], fields: string[], filename: string = 'log-analysis.csv'): void {
  if (logs.length === 0) return;
  const header = fields.map(escapeCSV).join(',');
  const rows = logs.map(log =>
    fields.map(f => escapeCSV((log as Record<string, unknown>)[f])).join(',')
  );
  const csv = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  triggerDownload(blob, filename);
}

// ═══════════════════════════════════════════════════════════════════
// BREAKDOWN EXPORTS
// ═══════════════════════════════════════════════════════════════════

/** Flatten breakdown result into tabular rows for export, including percentages. */
function flattenBreakdown(bd: BreakdownResult): Array<Record<string, string | number>> {
  const rows: Array<Record<string, string | number>> = [];
  for (const entry of bd.entries) {
    // Find max sub-rows across all breakdown fields
    const maxSubs = Math.max(1, ...bd.breakdownFields.map(bf =>
      entry.breakdowns[bf.key]?.length || 0
    ));
    // Denominator for % per breakdown field: primary count (each request has exactly one value).
    // Fall back to sum of sub counts if primary count is missing or top-K coverage is partial.
    const denomByField: Record<string, number> = {};
    for (const bf of bd.breakdownFields) {
      const subs = entry.breakdowns[bf.key] || [];
      const subTotal = subs.reduce((s, x) => s + x.count, 0);
      denomByField[bf.key] = entry.primaryCount > 0 ? entry.primaryCount : subTotal;
    }
    for (let i = 0; i < maxSubs; i++) {
      const row: Record<string, string | number> = {};
      row[bd.primaryLabel] = i === 0 ? entry.primaryValue : '';
      row[`${bd.primaryLabel} Count`] = i === 0 ? entry.primaryCount : '';
      for (const bf of bd.breakdownFields) {
        const sub = entry.breakdowns[bf.key]?.[i];
        row[bf.label] = sub?.value ?? '';
        row[`${bf.label} Count`] = sub?.count ?? '';
        const denom = denomByField[bf.key];
        row[`${bf.label} %`] = sub && denom > 0
          ? Math.round((sub.count / denom) * 10000) / 100  // 2 decimals
          : '';
      }
      rows.push(row);
    }
  }
  return rows;
}

/** Build per-breakdown-field pivoted rows: one row per (primary × sub-value) pair with count + %. */
function buildPerFieldRows(bd: BreakdownResult, bf: { key: string; label: string }): Array<Record<string, string | number>> {
  const rows: Array<Record<string, string | number>> = [];
  for (const entry of bd.entries) {
    const subs = entry.breakdowns[bf.key] || [];
    const subTotal = subs.reduce((s, x) => s + x.count, 0);
    const denom = entry.primaryCount > 0 ? entry.primaryCount : subTotal;
    if (subs.length === 0) {
      rows.push({
        [bd.primaryLabel]: entry.primaryValue,
        [`${bd.primaryLabel} Count`]: entry.primaryCount,
        [bf.label]: '(none)',
        Count: 0,
        '%': 0,
      });
    } else {
      for (const sub of subs) {
        rows.push({
          [bd.primaryLabel]: entry.primaryValue,
          [`${bd.primaryLabel} Count`]: entry.primaryCount,
          [bf.label]: sub.value || '(empty)',
          Count: sub.count,
          '%': denom > 0 ? Math.round((sub.count / denom) * 10000) / 100 : 0,
        });
      }
    }
  }
  return rows;
}

export function exportBreakdownAsCSV(bd: BreakdownResult, filename: string = 'field-breakdown.csv'): void {
  const rows = flattenBreakdown(bd);
  if (rows.length === 0) return;
  const cols = Object.keys(rows[0]);
  const header = cols.map(escapeCSV).join(',');
  const csvRows = rows.map(r => cols.map(c => escapeCSV(r[c])).join(','));
  const csv = [header, ...csvRows].join('\n');
  triggerDownload(new Blob([csv], { type: 'text/csv;charset=utf-8' }), filename);
}

export async function exportBreakdownAsExcel(bd: BreakdownResult, filename: string = 'field-breakdown.xlsx'): Promise<void> {
  const XLSX = await import('xlsx');
  const wb = XLSX.utils.book_new();

  // Sheet 1: Combined flat view (all breakdown fields side-by-side with % columns)
  const combined = flattenBreakdown(bd);
  if (combined.length > 0) {
    const ws = XLSX.utils.json_to_sheet(combined);
    // Format % columns as numbers with 2 decimals (Excel will show as 12.34, not 12.34%)
    XLSX.utils.book_append_sheet(wb, ws, 'Combined');
  }

  // Sheet(s) 2+: One sheet per breakdown field — pivoted (primary × sub-value × count × %)
  for (const bf of bd.breakdownFields) {
    const rows = buildPerFieldRows(bd, bf);
    if (rows.length === 0) continue;
    const ws = XLSX.utils.json_to_sheet(rows);
    // Excel sheet name max 31 chars, no [ ] / \ ? * :
    const safeName = bf.label.replace(/[\\/?*[\]:]/g, '_').slice(0, 31) || bf.key.slice(0, 31);
    XLSX.utils.book_append_sheet(wb, ws, safeName);
  }

  const buf = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  triggerDownload(new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), filename);
}

export async function exportBreakdownAsPDF(bd: BreakdownResult, filename: string = 'field-breakdown.pdf'): Promise<void> {
  const { default: jsPDF } = await import('jspdf');
  const autoTablePlugin = (await import('jspdf-autotable')).default;

  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();

  // Title page header
  doc.setFontSize(16);
  doc.setTextColor(30, 41, 59);
  doc.text(`Field Breakdown: ${bd.primaryLabel}`, 14, 15);
  doc.setFontSize(9);
  doc.setTextColor(120);
  doc.text(`Breakdown by: ${bd.breakdownFields.map(f => f.label).join(', ')}`, 14, 22);
  doc.text(`Total entries: ${bd.entries.length}  |  Generated: ${new Date().toLocaleString()}`, 14, 28);

  let cursorY = 35;

  // Render one table per breakdown field — each has only 4 columns (Primary | Sub | Count | %)
  for (let bfIdx = 0; bfIdx < bd.breakdownFields.length; bfIdx++) {
    const bf = bd.breakdownFields[bfIdx];

    // Section header
    if (cursorY > doc.internal.pageSize.getHeight() - 30) {
      doc.addPage();
      cursorY = 15;
    }
    doc.setFontSize(12);
    doc.setTextColor(30, 41, 59);
    doc.text(`${bf.label} Breakdown`, 14, cursorY);
    cursorY += 6;

    // Build rows: primary value | breakdown value | count | %
    const tableBody: string[][] = [];
    for (const entry of bd.entries) {
      const subs = entry.breakdowns[bf.key] || [];
      const subTotal = subs.reduce((s, x) => s + x.count, 0);
      const denom = entry.primaryCount > 0 ? entry.primaryCount : subTotal;
      if (subs.length === 0) {
        tableBody.push([entry.primaryValue, '(none)', '0', '0%']);
      } else {
        for (let i = 0; i < subs.length; i++) {
          const sub = subs[i];
          const pct = denom > 0 ? (sub.count / denom) * 100 : 0;
          tableBody.push([
            i === 0 ? `${entry.primaryValue}  (${entry.primaryCount})` : '',
            sub.value || '(empty)',
            String(sub.count),
            `${pct.toFixed(pct < 1 ? 2 : 1)}%`,
          ]);
        }
      }
    }

    const colWidth = (pageWidth - 20) / 4;

    autoTablePlugin(doc, {
      startY: cursorY,
      head: [[bd.primaryLabel, bf.label, 'Count', '%']],
      body: tableBody,
      styles: { fontSize: 7, cellPadding: 2, overflow: 'linebreak' },
      headStyles: { fillColor: [30, 41, 59], textColor: [226, 232, 240], fontSize: 8, fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      columnStyles: {
        0: { cellWidth: colWidth * 1.3 },
        1: { cellWidth: colWidth * 1.4 },
        2: { cellWidth: colWidth * 0.65, halign: 'right' },
        3: { cellWidth: colWidth * 0.65, halign: 'right' },
      },
      margin: { left: 10, right: 10 },
      didDrawPage: (_data: HookData) => {
        doc.setFontSize(7);
        doc.setTextColor(160);
        doc.text(
          `${bf.label} Breakdown  —  Page ${doc.getNumberOfPages()}`,
          pageWidth / 2, doc.internal.pageSize.getHeight() - 5,
          { align: 'center' },
        );
      },
    });

    cursorY = (doc as unknown as { lastAutoTable?: { finalY?: number } }).lastAutoTable?.finalY ?? cursorY + 20;
    cursorY += 12;
  }

  doc.save(filename);
}
