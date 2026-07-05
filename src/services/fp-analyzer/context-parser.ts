/**
 * Parse security event context string into structured exclusion rule context.
 * e.g. "parameter (input_file)" → { contextType: "CONTEXT_PARAMETER", contextName: "input_file" }
 */
export function parseContext(contextStr: string): { contextType: string; contextName: string } {
  const str = (contextStr || '').trim();
  const typeMap: Record<string, string> = {
    parameter: 'CONTEXT_PARAMETER',
    cookie: 'CONTEXT_COOKIE',
    header: 'CONTEXT_HEADER',
  };

  // "parameter (name)" / "cookie (name)" / "header (name)" — keyword + captured name.
  const match = str.match(/^(parameter|cookie|header)\s*\(([^)]+)\)/i);
  if (match) {
    return { contextType: typeMap[match[1].toLowerCase()], contextName: match[2].trim() };
  }
  // Paren-less leading keyword (no name available).
  const word = str.match(/^(parameter|cookie|header)\b/i);
  if (word) {
    return { contextType: typeMap[word[1].toLowerCase()], contextName: '' };
  }

  if (/url|uri/i.test(str)) return { contextType: 'CONTEXT_URL', contextName: '' };
  if (/body/i.test(str)) return { contextType: 'CONTEXT_BODY', contextName: '' };

  // Unrecognized context — default to CONTEXT_ANY so the generated exclusion still matches the
  // detection. Defaulting to CONTEXT_PARAMETER would emit a rule that silently never matches a
  // non-parameter detection (e.g. a URI/body signature), leaving the false positive un-excluded.
  return { contextType: 'CONTEXT_ANY', contextName: '' };
}
