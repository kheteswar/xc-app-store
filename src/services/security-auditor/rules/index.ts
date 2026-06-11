// ═══════════════════════════════════════════════════════════════════════════
// Security Rules Index
// Exports all security rules for the audit engine
// ═══════════════════════════════════════════════════════════════════════════

import { catalogRules } from './catalog.rules';
import type { SecurityRule } from '../types';

// The consolidated, field-accurate catalog is the single source of truth.
// (The earlier per-domain rule files read incorrect XC field paths and have
// been superseded by catalog.rules.ts + xc-extractors.ts.)
export const allRules: SecurityRule[] = [...catalogRules];

export { catalogRules };

// Get rules by category
export const getRulesByCategory = (category: string): SecurityRule[] => {
  return allRules.filter(rule => rule.category === category);
};

// Get rules by object type
export const getRulesByObjectType = (objectType: string): SecurityRule[] => {
  return allRules.filter(rule => rule.appliesTo.includes(objectType as any));
};

// Get rule by ID
export const getRuleById = (id: string): SecurityRule | undefined => {
  return allRules.find(rule => rule.id === id);
};

// Rule statistics
export const getRuleStats = () => {
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const byObjectType: Record<string, number> = {};

  for (const rule of allRules) {
    byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
    bySeverity[rule.severity] = (bySeverity[rule.severity] || 0) + 1;
    
    for (const objType of rule.appliesTo) {
      byObjectType[objType] = (byObjectType[objType] || 0) + 1;
    }
  }

  return {
    total: allRules.length,
    byCategory,
    bySeverity,
    byObjectType,
  };
};
