import * as XLSX from 'xlsx';
import type { Direction, MappingEntry, SupportedExt } from './types';
import { substituteText } from './substitution';
import {
  extractOoxmlText,
  loadZip,
  substituteOoxml,
  zipToBlob,
} from './ooxml';

/**
 * Optional auto-redaction map computed once per file (see auto-rules.ts).
 * Each processor receives the precomputed map and threads it through the
 * sync OOXML walker, avoiding awaiting WebCrypto on every text node.
 */
export type AutoMap = Map<string, string> | undefined;

const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
const PPTX_MIME = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

// MIME type per text-based extension — used so the output Blob's Content-Type
// matches the file's nature (helps browser preview / drag-and-drop targets).
const TEXT_MIMES: Record<string, string> = {
  '.txt': 'text/plain;charset=utf-8',
  '.csv': 'text/csv;charset=utf-8',
  '.tsv': 'text/tab-separated-values;charset=utf-8',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.yaml': 'application/x-yaml',
  '.yml': 'application/x-yaml',
  '.log': 'text/plain;charset=utf-8',
  '.md': 'text/markdown;charset=utf-8',
  '.html': 'text/html;charset=utf-8',
  '.htm': 'text/html;charset=utf-8',
  '.ini': 'text/plain;charset=utf-8',
  '.conf': 'text/plain;charset=utf-8',
  '.cfg': 'text/plain;charset=utf-8',
};

// ─── Per-format processors ──────────────────────────────────────────────

/**
 * Plain-text processor — used for .txt, .csv, .json, .xml, .yaml, .log, …
 * Decodes UTF-8, runs substitution over the whole buffer, re-encodes as
 * UTF-8 with the appropriate MIME type. We deliberately do NOT try to
 * parse JSON/XML/YAML structurally: the mapping rules are user-authored
 * and the user expects literal text substitution (same model as .txt).
 */
export function makeTextProcessor(mime: string) {
  return async (
    buf: ArrayBuffer,
    entries: MappingEntry[],
    direction: Direction,
    autoMap?: AutoMap,
  ): Promise<Blob> => {
    const text = new TextDecoder('utf-8').decode(buf);
    const out = substituteText(text, entries, direction, autoMap);
    return new Blob([out], { type: mime });
  };
}

export const processTxt = makeTextProcessor(TEXT_MIMES['.txt']);

/** Word docs: walk document.xml, header*.xml, footer*.xml, footnotes/endnotes. */
export async function processDocx(
  buf: ArrayBuffer,
  entries: MappingEntry[],
  direction: Direction,
  autoMap?: AutoMap,
): Promise<Blob> {
  const zip = await loadZip(buf);
  const targets = Object.keys(zip.files).filter((name) =>
    /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(name),
  );
  for (const name of targets) {
    const file = zip.file(name);
    if (!file) continue;
    const xml = await file.async('string');
    zip.file(name, substituteOoxml(xml, entries, direction, 'w:p', 'w:t', autoMap));
  }
  return zipToBlob(zip, DOCX_MIME);
}

/** PowerPoint: walk slides, slideLayouts, slideMasters, notesSlides. */
export async function processPptx(
  buf: ArrayBuffer,
  entries: MappingEntry[],
  direction: Direction,
  autoMap?: AutoMap,
): Promise<Blob> {
  const zip = await loadZip(buf);
  const targets = Object.keys(zip.files).filter((name) =>
    /^ppt\/(slides|slideLayouts|slideMasters|notesSlides)\/[^/]+\.xml$/.test(name),
  );
  for (const name of targets) {
    const file = zip.file(name);
    if (!file) continue;
    const xml = await file.async('string');
    zip.file(name, substituteOoxml(xml, entries, direction, 'a:p', 'a:t', autoMap));
  }
  return zipToBlob(zip, PPTX_MIME);
}

/**
 * Excel: walk the workbook as an OOXML ZIP (like docx/pptx) so that styles,
 * conditional formatting, merged cells, charts, images, drawings, themes,
 * data validations, and pivot tables all pass through byte-identical.
 *
 * Text in xlsx lives in three places:
 *   - xl/sharedStrings.xml  — <si><t>...</t></si> / <si><r><t>...</t></r></si>
 *   - xl/worksheets/sheet*.xml — inline strings: <c t="inlineStr"><is><t>...</t></is></c>
 *   - xl/comments*.xml      — <comment><text><r><t>...</t></r></text></comment>
 *
 * We deliberately do NOT pass this through XLSX.read/XLSX.write: the
 * community edition of the xlsx library does not write styles, so a
 * round-trip strips all visual formatting from the output workbook.
 */
export async function processXlsx(
  buf: ArrayBuffer,
  entries: MappingEntry[],
  direction: Direction,
  autoMap?: AutoMap,
): Promise<Blob> {
  const zip = await loadZip(buf);
  const sharedStringsRe = /^xl\/sharedStrings\.xml$/;
  const sheetRe = /^xl\/worksheets\/sheet\d+\.xml$/;
  const commentsRe = /^xl\/comments\d+\.xml$/;

  for (const name of Object.keys(zip.files)) {
    const file = zip.file(name);
    if (!file) continue;

    let paraTag: string | null = null;
    if (sharedStringsRe.test(name)) paraTag = 'si';
    else if (sheetRe.test(name)) paraTag = 'is';
    else if (commentsRe.test(name)) paraTag = 'text';
    if (!paraTag) continue;

    const xml = await file.async('string');
    zip.file(name, substituteOoxml(xml, entries, direction, paraTag, 't', autoMap));
  }
  return zipToBlob(zip, XLSX_MIME);
}

// ─── Text extraction (for scan + residual check) ────────────────────────

export async function extractText(buf: ArrayBuffer, ext: SupportedExt): Promise<string> {
  if (ext in TEXT_MIMES) {
    return new TextDecoder('utf-8').decode(buf);
  }
  if (ext === '.docx') {
    const zip = await loadZip(buf);
    const targets = Object.keys(zip.files).filter((n) =>
      /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(n),
    );
    const chunks: string[] = [];
    for (const name of targets) {
      const file = zip.file(name);
      if (!file) continue;
      chunks.push(extractOoxmlText(await file.async('string'), 'w:t'));
    }
    return chunks.join('\n');
  }
  if (ext === '.pptx') {
    const zip = await loadZip(buf);
    const targets = Object.keys(zip.files).filter((n) =>
      /^ppt\/(slides|slideLayouts|slideMasters|notesSlides)\/[^/]+\.xml$/.test(n),
    );
    const chunks: string[] = [];
    for (const name of targets) {
      const file = zip.file(name);
      if (!file) continue;
      chunks.push(extractOoxmlText(await file.async('string'), 'a:t'));
    }
    return chunks.join('\n');
  }
  if (ext === '.xlsx') {
    const wb = XLSX.read(buf, { type: 'array' });
    const chunks: string[] = [];
    for (const sheet of wb.SheetNames) {
      const ws = wb.Sheets[sheet];
      if (!ws) continue;
      for (const addr of Object.keys(ws)) {
        if (addr.startsWith('!')) continue;
        const v = ws[addr]?.v;
        if (typeof v === 'string') chunks.push(v);
      }
    }
    return chunks.join('\n');
  }
  throw new Error(`Unsupported extension: ${ext}`);
}

export const PROCESSORS: Record<SupportedExt,
  (buf: ArrayBuffer, entries: MappingEntry[], direction: Direction, autoMap?: AutoMap) => Promise<Blob>
> = {
  '.txt': processTxt,
  '.docx': processDocx,
  '.pptx': processPptx,
  '.xlsx': processXlsx,
  '.csv': makeTextProcessor(TEXT_MIMES['.csv']),
  '.tsv': makeTextProcessor(TEXT_MIMES['.tsv']),
  '.json': makeTextProcessor(TEXT_MIMES['.json']),
  '.xml': makeTextProcessor(TEXT_MIMES['.xml']),
  '.yaml': makeTextProcessor(TEXT_MIMES['.yaml']),
  '.yml': makeTextProcessor(TEXT_MIMES['.yml']),
  '.log': makeTextProcessor(TEXT_MIMES['.log']),
  '.md': makeTextProcessor(TEXT_MIMES['.md']),
  '.html': makeTextProcessor(TEXT_MIMES['.html']),
  '.htm': makeTextProcessor(TEXT_MIMES['.htm']),
  '.ini': makeTextProcessor(TEXT_MIMES['.ini']),
  '.conf': makeTextProcessor(TEXT_MIMES['.conf']),
  '.cfg': makeTextProcessor(TEXT_MIMES['.cfg']),
};
