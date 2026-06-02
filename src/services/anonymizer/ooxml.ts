import JSZip from 'jszip';
import type { Direction, MappingEntry } from './types';
import { substituteText } from './substitution';

/**
 * OOXML formats (docx, pptx, xlsx) are ZIPs of XML files.
 * Text lives inside <w:t> (Word), <a:t> (PowerPoint), <t> (Excel sharedStrings).
 *
 * Cross-run substitution problem: in Word/PowerPoint, a real value like
 * "Acme Bank" can be split across two text runs because of inline formatting:
 *   <w:r><w:t>Acme</w:t></w:r><w:r><w:t> Bank</w:t></w:r>
 * Per-text-node substitution misses this. We mirror the Python tool's
 * paragraph-collapse strategy: if the joined paragraph text would change
 * after substitution but the per-node passes did not catch it, we put the
 * entire substituted text in the first <w:t>/<a:t> of the paragraph and
 * blank the rest. Formatting on the trailing runs is lost, but only on
 * paragraphs where a cross-run match was actually found — acceptable
 * trade-off for a redaction tool.
 */

// Paragraph/run-container tag. Word/PowerPoint use 'w:p'/'a:p', Excel uses
// 'si' (sharedStrings), 'is' (inline strings), 'text' (comments).
export type ParagraphTag = string;
// Text-leaf tag. Word/PowerPoint use 'w:t'/'a:t', Excel uses 't'.
export type TextTag = string;

export function loadZip(buf: ArrayBuffer): Promise<JSZip> {
  return JSZip.loadAsync(buf);
}

export async function zipToBlob(zip: JSZip, mime: string): Promise<Blob> {
  return zip.generateAsync({
    type: 'blob',
    mimeType: mime,
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  });
}

/**
 * Apply substitution to every text node in an XML document, then handle
 * cross-run matches by collapsing paragraphs whose joined text still has
 * a substitutable value after the per-node pass.
 *
 * Uses DOMParser/XMLSerializer (browser-native).
 */
export function substituteOoxml(
  xmlString: string,
  entries: MappingEntry[],
  direction: Direction,
  paraTag: ParagraphTag,
  textTag: TextTag,
  autoMap?: Map<string, string>,
): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlString, 'application/xml');

  // Reject malformed XML — if the input was bad we'd silently return
  // a parser error document otherwise.
  if (doc.getElementsByTagName('parsererror').length > 0) {
    return xmlString;
  }

  // Pass 1: per-text-node substitution (preserves formatting).
  const textNodes = Array.from(doc.getElementsByTagName(textTag));
  for (const t of textNodes) {
    const original = t.textContent ?? '';
    const replaced = substituteText(original, entries, direction, autoMap);
    if (replaced !== original) {
      t.textContent = replaced;
      // OOXML preserves leading/trailing whitespace only when xml:space="preserve".
      if (replaced !== replaced.trim() && !t.getAttribute('xml:space')) {
        t.setAttribute('xml:space', 'preserve');
      }
    }
  }

  // Pass 2: cross-run collapse on each paragraph.
  const paragraphs = Array.from(doc.getElementsByTagName(paraTag));
  for (const p of paragraphs) {
    const tEls = Array.from(p.getElementsByTagName(textTag));
    if (tEls.length < 2) continue;

    const joined = tEls.map((el) => el.textContent ?? '').join('');
    const substituted = substituteText(joined, entries, direction, autoMap);
    if (substituted === joined) continue;

    // Cross-run match found. Put the full substituted text in the first
    // text node, blank the rest. Preserve whitespace.
    tEls[0].textContent = substituted;
    if (!tEls[0].getAttribute('xml:space')) {
      tEls[0].setAttribute('xml:space', 'preserve');
    }
    for (let i = 1; i < tEls.length; i++) {
      tEls[i].textContent = '';
    }
  }

  const serialized = new XMLSerializer().serializeToString(doc);

  // XMLSerializer drops the <?xml ... ?> declaration. Word is lenient about
  // missing declarations; Excel is not — restore the original prolog if it
  // had one so the output file opens without a "repair" prompt.
  const declMatch = xmlString.match(/^﻿?\s*<\?xml[^?]*\?>/);
  if (declMatch && !/^\s*<\?xml/.test(serialized)) {
    return declMatch[0] + serialized;
  }
  return serialized;
}

/**
 * Extract all visible text from an OOXML document for scanning.
 */
export function extractOoxmlText(xmlString: string, textTag: TextTag): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlString, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length > 0) return '';
  return Array.from(doc.getElementsByTagName(textTag))
    .map((el) => el.textContent ?? '')
    .join('\n');
}
