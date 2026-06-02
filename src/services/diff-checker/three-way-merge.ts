import { myersDiff } from './diff-engine';
import type { MergeConflict, MergeResult, MergeSegment, ThreeWayInput } from './types';

interface Hunk {
  baseStart: number;
  baseEnd: number;
  replacement: string[];
}

function arrayEq(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function computeHunks(base: string[], side: string[]): Hunk[] {
  const ops = myersDiff(base, side);
  const hunks: Hunk[] = [];
  let i = 0;
  while (i < ops.length) {
    if (ops[i].type === 'equal') {
      i++;
      continue;
    }
    const hunkOpStart = i;
    const baseIndices: number[] = [];
    const rightIndices: number[] = [];
    while (i < ops.length && ops[i].type !== 'equal') {
      const op = ops[i];
      if (op.type === 'delete') baseIndices.push(op.leftIdx);
      else if (op.type === 'insert') rightIndices.push(op.rightIdx);
      i++;
    }

    let baseStart: number;
    let baseEnd: number;
    if (baseIndices.length > 0) {
      baseStart = baseIndices[0];
      baseEnd = baseIndices[baseIndices.length - 1] + 1;
    } else {
      if (hunkOpStart > 0) {
        const prev = ops[hunkOpStart - 1];
        if (prev.type === 'equal') {
          baseStart = prev.leftIdx + 1;
        } else {
          baseStart = 0;
        }
      } else {
        baseStart = 0;
      }
      baseEnd = baseStart;
    }

    const replacement = rightIndices.map(idx => side[idx]);
    hunks.push({ baseStart, baseEnd, replacement });
  }
  return hunks;
}

function applyHunksInRegion(base: string[], hunks: Hunk[], regionStart: number, regionEnd: number): string[] {
  const out: string[] = [];
  let cursor = regionStart;
  const sorted = [...hunks].sort((a, b) => a.baseStart - b.baseStart);
  for (const h of sorted) {
    while (cursor < h.baseStart && cursor < regionEnd) {
      out.push(base[cursor]);
      cursor++;
    }
    out.push(...h.replacement);
    cursor = Math.max(cursor, h.baseEnd);
  }
  while (cursor < regionEnd) {
    out.push(base[cursor]);
    cursor++;
  }
  return out;
}

export function threeWayMerge(input: ThreeWayInput): MergeResult {
  const baseL = input.base.split('\n');
  const leftL = input.left.split('\n');
  const rightL = input.right.split('\n');

  const leftHunks = computeHunks(baseL, leftL);
  const rightHunks = computeHunks(baseL, rightL);

  const segments: MergeSegment[] = [];
  const conflicts: MergeConflict[] = [];
  let autoResolved = 0;

  let baseIdx = 0;
  let li = 0;
  let ri = 0;

  while (true) {
    const leftH = li < leftHunks.length ? leftHunks[li] : null;
    const rightH = ri < rightHunks.length ? rightHunks[ri] : null;

    let nextHunkStart = baseL.length;
    if (leftH && leftH.baseStart < nextHunkStart) nextHunkStart = leftH.baseStart;
    if (rightH && rightH.baseStart < nextHunkStart) nextHunkStart = rightH.baseStart;

    if (nextHunkStart > baseIdx) {
      const unchanged = baseL.slice(baseIdx, nextHunkStart);
      if (unchanged.length > 0) segments.push({ type: 'context', lines: unchanged });
      baseIdx = nextHunkStart;
    }

    if (!leftH && !rightH) {
      if (baseIdx < baseL.length) {
        segments.push({ type: 'context', lines: baseL.slice(baseIdx) });
        baseIdx = baseL.length;
      }
      break;
    }

    const leftStartsHere = !!leftH && leftH.baseStart === baseIdx;
    const rightStartsHere = !!rightH && rightH.baseStart === baseIdx;

    if (leftStartsHere && rightStartsHere) {
      let combinedEnd = Math.max(leftH!.baseEnd, rightH!.baseEnd);
      const leftAccum: Hunk[] = [leftH!];
      const rightAccum: Hunk[] = [rightH!];
      li++; ri++;
      let extended = true;
      while (extended) {
        extended = false;
        const nl = li < leftHunks.length ? leftHunks[li] : null;
        const nr = ri < rightHunks.length ? rightHunks[ri] : null;
        if (nl && nl.baseStart < combinedEnd) {
          leftAccum.push(nl);
          combinedEnd = Math.max(combinedEnd, nl.baseEnd);
          li++;
          extended = true;
        }
        if (nr && nr.baseStart < combinedEnd) {
          rightAccum.push(nr);
          combinedEnd = Math.max(combinedEnd, nr.baseEnd);
          ri++;
          extended = true;
        }
      }

      const baseChunk = baseL.slice(baseIdx, combinedEnd);
      const leftChunk = applyHunksInRegion(baseL, leftAccum, baseIdx, combinedEnd);
      const rightChunk = applyHunksInRegion(baseL, rightAccum, baseIdx, combinedEnd);

      if (arrayEq(leftChunk, rightChunk)) {
        if (leftChunk.length > 0) segments.push({ type: 'auto-both', lines: leftChunk });
        autoResolved++;
      } else {
        const id = `c${conflicts.length}`;
        conflicts.push({
          id,
          baseStart: baseIdx,
          baseEnd: combinedEnd - 1,
          baseLines: baseChunk,
          leftLines: leftChunk,
          rightLines: rightChunk,
          resolution: undefined,
        });
        segments.push({ type: 'conflict', lines: [], conflictId: id });
      }
      baseIdx = combinedEnd;
    } else if (leftStartsHere) {
      if (leftH!.replacement.length > 0) segments.push({ type: 'auto-left', lines: leftH!.replacement });
      autoResolved++;
      baseIdx = leftH!.baseEnd;
      li++;
    } else if (rightStartsHere) {
      if (rightH!.replacement.length > 0) segments.push({ type: 'auto-right', lines: rightH!.replacement });
      autoResolved++;
      baseIdx = rightH!.baseEnd;
      ri++;
    } else {
      break;
    }
  }

  const resolvedLines = renderResolved(segments, conflicts);
  return { resolvedLines, segments, conflicts, autoResolved, conflictCount: conflicts.length };
}

export function renderResolved(segments: MergeSegment[], conflicts: MergeConflict[]): string[] {
  const out: string[] = [];
  for (const seg of segments) {
    if (seg.type === 'conflict') {
      const conf = conflicts.find(c => c.id === seg.conflictId);
      if (!conf) continue;
      if (conf.resolution === 'left') out.push(...conf.leftLines);
      else if (conf.resolution === 'right') out.push(...conf.rightLines);
      else if (conf.resolution === 'base') out.push(...conf.baseLines);
      else if (conf.resolution === 'manual' && conf.manualContent !== undefined) {
        out.push(...conf.manualContent.split('\n'));
      } else {
        out.push(`<<<<<<< LEFT`);
        out.push(...conf.leftLines);
        out.push(`||||||| BASE`);
        out.push(...conf.baseLines);
        out.push(`=======`);
        out.push(...conf.rightLines);
        out.push(`>>>>>>> RIGHT`);
      }
    } else {
      out.push(...seg.lines);
    }
  }
  return out;
}
