/**
 * Sentori Runtime AnomalyDetector
 * Runs AnomalyRules against a ToolCallEvent stream and produces a risk assessment.
 */

import type { ToolCallEvent } from './event-schema';
import { type AnomalyRule, type AnomalyMatch, DEFAULT_RULES } from './anomaly-rules';

export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export interface AnalysisResult {
  matches: AnomalyMatch[];
  riskScore: number;   // 0-100, weighted aggregate
  riskLevel: RiskLevel;
}

// ---------------------------------------------------------------------------
// Risk score → level mapping
// ---------------------------------------------------------------------------

function scoreToLevel(score: number): RiskLevel {
  if (score === 0) return 'safe';
  if (score <= 25) return 'low';
  if (score <= 50) return 'medium';
  if (score <= 75) return 'high';
  return 'critical';
}

/**
 * Combine match scores into a single 0-100 aggregate.
 *
 * Strategy: take the highest individual score as the base, then add 50% of
 * each subsequent match score (diminishing contribution). Cap at 100.
 *
 * This ensures:
 *   - A single critical match (score=90) → riskScore ≈ 90 → 'critical'
 *   - Multiple medium matches accumulate, eventually crossing thresholds
 *   - The total never exceeds 100
 */
function combineScores(matches: AnomalyMatch[]): number {
  if (matches.length === 0) return 0;

  const sorted = [...matches].map((m) => m.score).sort((a, b) => b - a);
  let total = sorted[0];

  for (let i = 1; i < sorted.length; i++) {
    total += sorted[i] * 0.5;
  }

  return Math.min(100, Math.round(total));
}

// ---------------------------------------------------------------------------
// AnomalyDetector
// ---------------------------------------------------------------------------

export class AnomalyDetector {
  private rules: AnomalyRule[];

  constructor(rules?: AnomalyRule[]) {
    this.rules = rules ? [...rules] : [...DEFAULT_RULES];
  }

  /**
   * Analyse a sequence of ToolCallEvents and return a risk assessment.
   * Rules are run in registration order; all matches are collected.
   */
  analyze(events: ToolCallEvent[]): AnalysisResult {
    const matches: AnomalyMatch[] = [];

    for (const rule of this.rules) {
      const ruleMatches = rule.detect(events);
      matches.push(...ruleMatches);
    }

    const riskScore = combineScores(matches);
    const riskLevel = scoreToLevel(riskScore);

    return { matches, riskScore, riskLevel };
  }

  /** Register an additional rule (appended to the evaluation order). */
  addRule(rule: AnomalyRule): void {
    this.rules.push(rule);
  }

  /** Returns a snapshot of currently registered rule IDs. */
  getRuleIds(): string[] {
    return this.rules.map((r) => r.id);
  }
}
