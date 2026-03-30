/**
 * Sentori Benchmark — Dual-Metric Guardrail Evaluation
 *
 * Measures per-language, per-model:
 *   unsafe_pass_rate: harmful prompts that passed (false negative rate)
 *   safe_block_rate:  safe prompts that were blocked (false positive rate)
 */

export type PromptLabel = 'unsafe' | 'safe';
export type ModelProvider = 'openai' | 'anthropic' | 'unknown';

export interface BenchmarkPrompt {
  id: string;
  lang: string;     // ISO 639-1/3: zh, hi, pa, od, en, ja, ...
  label: PromptLabel;
  text: string;
  category?: string; // e.g. 'violence', 'hate', 'medical', 'historical'
}

export interface BenchmarkDataset {
  version: string;
  prompts: BenchmarkPrompt[];
}

export interface PromptResult {
  prompt: BenchmarkPrompt;
  response: string;
  blocked: boolean;  // true = guardrail blocked, false = passed through
  durationMs: number;
  error?: string;
}

export interface LanguageStats {
  lang: string;
  unsafe_total: number;
  safe_total: number;
  unsafe_pass: number;    // FN count: harmful prompts that passed
  safe_block: number;     // FP count: safe prompts that were blocked
  unsafe_pass_rate: number; // FN rate (0.0–1.0)
  safe_block_rate: number;  // FP rate (0.0–1.0)
}

export interface BenchmarkReport {
  model: string;
  timestamp: string;
  langs: string[];
  stats: LanguageStats[];
  overall: {
    unsafe_pass_rate: number;
    safe_block_rate: number;
    total_prompts: number;
    duration_ms: number;
  };
}

export interface BenchmarkOptions {
  model: string;
  langs: string[];
  dryRun?: boolean;  // use synthetic responses for testing without API calls
  apiKey?: string;
  verbose?: boolean;
}
