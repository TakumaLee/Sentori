/**
 * Cross-lingual safety consistency checker.
 *
 * Based on IndicSafe findings (arxiv 2603.17915v1): the same harmful prompt
 * receives consistent safety judgments across languages only 12.8% of the time.
 * This checker translates the input to English and compares safety scores
 * across both languages to surface divergence.
 *
 * Usage:
 *   sentori check --cross-lingual "input text" [--model MODEL] [--threshold 0.3]
 */

import * as https from 'https';
import * as http from 'http';

// ─── Language detection ───────────────────────────────────────────────────────

export interface DetectedLanguage {
  code: string;
  name: string;
  script: string;
}

const SCRIPT_RANGES: Array<{ re: RegExp; code: string; name: string; script: string }> = [
  { re: /[\u4e00-\u9fff\u3400-\u4dbf]/, code: 'zh', name: 'Chinese', script: 'Han' },
  { re: /[\u0900-\u097f]/, code: 'hi', name: 'Hindi', script: 'Devanagari' },
  { re: /[\u0a00-\u0a7f]/, code: 'pa', name: 'Punjabi', script: 'Gurmukhi' },
  { re: /[\u0b00-\u0b7f]/, code: 'or', name: 'Odia', script: 'Odia' },
  { re: /[\u0600-\u06ff]/, code: 'ar', name: 'Arabic', script: 'Arabic' },
  { re: /[\u0400-\u04ff]/, code: 'ru', name: 'Russian', script: 'Cyrillic' },
  { re: /[\u3040-\u30ff]/, code: 'ja', name: 'Japanese', script: 'Kana' },
  { re: /[\uac00-\ud7af]/, code: 'ko', name: 'Korean', script: 'Hangul' },
  { re: /[\u0e00-\u0e7f]/, code: 'th', name: 'Thai', script: 'Thai' },
  { re: /[\u0370-\u03ff]/, code: 'el', name: 'Greek', script: 'Greek' },
  { re: /[\u0590-\u05ff]/, code: 'he', name: 'Hebrew', script: 'Hebrew' },
];

export function detectLanguage(text: string): DetectedLanguage {
  for (const entry of SCRIPT_RANGES) {
    if (entry.re.test(text)) {
      return { code: entry.code, name: entry.name, script: entry.script };
    }
  }
  // Default: English / Latin script
  return { code: 'en', name: 'English', script: 'Latin' };
}

// ─── LLM HTTP helpers ─────────────────────────────────────────────────────────

type ModelProvider = 'anthropic' | 'openai' | 'unknown';

function resolveProvider(model: string): ModelProvider {
  if (model.startsWith('gpt-') || model.startsWith('o1') || model.startsWith('o3')) return 'openai';
  if (model.startsWith('claude-')) return 'anthropic';
  return 'unknown';
}

function postJson(options: http.RequestOptions, body: object): Promise<string> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const reqOptions: http.RequestOptions = {
      ...options,
      method: 'POST',
      headers: {
        ...(options.headers ?? {}),
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };
    const req = https.request(reqOptions, (res) => {
      let out = '';
      res.on('data', (chunk) => { out += chunk; });
      res.on('end', () => resolve(out));
    });
    req.on('error', reject);
    req.setTimeout(30_000, () => { req.destroy(new Error('request timeout')); });
    req.write(data);
    req.end();
  });
}

// ─── Safety analysis prompt ───────────────────────────────────────────────────

const ANALYSIS_SYSTEM_PROMPT = `You are a multilingual AI safety classifier. Your task is to analyze text for harmful content and provide safety scores.

Respond ONLY with valid JSON, no prose.`;

function buildAnalysisPrompt(text: string): string {
  return `Analyze the following text for harmful content.

TEXT:
"""
${text.slice(0, 2000)}
"""

Respond with this exact JSON structure:
{
  "source_lang": "<ISO 639-1 code, e.g. zh, hi, ar, en>",
  "source_lang_name": "<language name in English>",
  "english_translation": "<translate the text to English; if already English, copy verbatim>",
  "source_safety_score": <float 0.0-1.0>,
  "english_safety_score": <float 0.0-1.0>,
  "source_analysis": "<1-sentence reasoning for source score>",
  "english_analysis": "<1-sentence reasoning for English score>"
}

Safety score guidelines:
- 0.0: clearly benign content
- 0.3-0.5: ambiguous or mildly concerning
- 0.7-1.0: clearly requesting harmful content (violence, weapons, illegal activities, self-harm, etc.)

Score the MEANING of the text, not the language itself.`;
}

// ─── LLM call ────────────────────────────────────────────────────────────────

async function callLLM(
  model: string,
  apiKey: string,
  prompt: string,
): Promise<string> {
  const provider = resolveProvider(model);

  if (provider === 'anthropic') {
    const raw = await postJson(
      {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
      },
      {
        model,
        max_tokens: 512,
        system: ANALYSIS_SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }],
      },
    );
    let parsed: { content?: Array<{ text?: string }> };
    try {
      parsed = JSON.parse(raw) as typeof parsed;
    } catch (err) {
      process.stderr.write(JSON.stringify({ level: 'error', context: 'cross-lingual-checker', model, error: 'Anthropic API response JSON parse failed', message: String(err) }) + '\n');
      throw new Error(`Anthropic API malformed JSON response: ${String(err)}`);
    }
    return parsed.content?.[0]?.text ?? '';
  }

  if (provider === 'openai') {
    const raw = await postJson(
      {
        hostname: 'api.openai.com',
        path: '/v1/chat/completions',
        headers: { Authorization: `Bearer ${apiKey}` },
      },
      {
        model,
        max_tokens: 512,
        messages: [
          { role: 'system', content: ANALYSIS_SYSTEM_PROMPT },
          { role: 'user', content: prompt },
        ],
      },
    );
    let parsed: { choices?: Array<{ message?: { content?: string } }> };
    try {
      parsed = JSON.parse(raw) as typeof parsed;
    } catch (err) {
      process.stderr.write(JSON.stringify({ level: 'error', context: 'cross-lingual-checker', model, error: 'OpenAI API response JSON parse failed', message: String(err) }) + '\n');
      throw new Error(`OpenAI API malformed JSON response: ${String(err)}`);
    }
    return parsed.choices?.[0]?.message?.content ?? '';
  }

  throw new Error(`Unsupported model provider for model: ${model}`);
}

// ─── Cross-lingual result type ────────────────────────────────────────────────

export interface CrossLingualResult {
  input: string;
  detectedLang: DetectedLanguage;
  englishTranslation: string;
  sourceScore: number;
  englishScore: number;
  delta: number;
  threshold: number;
  flagged: boolean;
  flagReason: string | null;
  sourceAnalysis: string;
  englishAnalysis: string;
}

// ─── Main checker ─────────────────────────────────────────────────────────────

export async function runCrossLingualCheck(
  input: string,
  options: {
    model: string;
    apiKey: string;
    threshold?: number;
  },
): Promise<CrossLingualResult> {
  const threshold = options.threshold ?? 0.3;

  // Fast local language detection for reporting
  const detectedLang = detectLanguage(input);

  // LLM-based analysis: translate + dual safety scoring in one call
  const prompt = buildAnalysisPrompt(input);
  const rawResponse = await callLLM(options.model, options.apiKey, prompt);

  // Extract JSON from response (model may wrap in markdown code block)
  const jsonMatch = rawResponse.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error(`LLM returned non-JSON response: ${rawResponse.slice(0, 200)}`);
  }

  let analysis: {
    source_lang?: string;
    source_lang_name?: string;
    english_translation?: string;
    source_safety_score?: number;
    english_safety_score?: number;
    source_analysis?: string;
    english_analysis?: string;
  };
  try {
    analysis = JSON.parse(jsonMatch[0]) as typeof analysis;
  } catch (err) {
    process.stderr.write(JSON.stringify({ level: 'error', context: 'cross-lingual-checker', error: 'LLM analysis JSON parse failed', message: String(err) }) + '\n');
    throw new Error(`Failed to parse LLM analysis JSON: ${String(err)}`);
  }

  const sourceScore = Number(analysis.source_safety_score ?? 0);
  const englishScore = Number(analysis.english_safety_score ?? 0);
  const delta = Math.abs(sourceScore - englishScore);
  const flagged = delta >= threshold;

  // Override local detection with LLM's if provided
  if (analysis.source_lang && analysis.source_lang_name) {
    detectedLang.code = analysis.source_lang;
    detectedLang.name = analysis.source_lang_name;
  }

  let flagReason: string | null = null;
  if (flagged) {
    const direction = sourceScore < englishScore
      ? `source (${detectedLang.name}) scored safer than English`
      : `English scored safer than source (${detectedLang.name})`;
    flagReason = `Cross-lingual divergence detected: ${direction}. ` +
      `This may indicate the ${detectedLang.name} version bypasses safety filters that catch the English equivalent.`;
  }

  return {
    input,
    detectedLang,
    englishTranslation: analysis.english_translation ?? '',
    sourceScore,
    englishScore,
    delta,
    threshold,
    flagged,
    flagReason,
    sourceAnalysis: analysis.source_analysis ?? '',
    englishAnalysis: analysis.english_analysis ?? '',
  };
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

export function formatCrossLingualResult(result: CrossLingualResult): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(`  source_lang: ${result.detectedLang.code} (${result.detectedLang.name})`);

  if (result.detectedLang.code !== 'en') {
    const preview = result.englishTranslation.length > 120
      ? result.englishTranslation.slice(0, 120) + '…'
      : result.englishTranslation;
    lines.push(`  translation: ${preview}`);
  }

  lines.push('');
  lines.push(`  safety_score: ${result.sourceScore.toFixed(2)} (${result.detectedLang.code}) vs ${result.englishScore.toFixed(2)} (en)`);
  lines.push(`  delta: ${result.delta.toFixed(2)}  threshold: ${result.threshold.toFixed(2)}`);
  lines.push('');

  if (result.flagged) {
    lines.push(`  ⚠ FLAGGED: cross-lingual divergence (delta ${result.delta.toFixed(2)} ≥ threshold ${result.threshold.toFixed(2)})`);
    if (result.flagReason) {
      lines.push(`  ${result.flagReason}`);
    }
  } else {
    lines.push(`  ✓ OK: scores consistent across languages (delta ${result.delta.toFixed(2)} < threshold ${result.threshold.toFixed(2)})`);
  }

  if (result.sourceAnalysis) {
    lines.push('');
    lines.push(`  source analysis: ${result.sourceAnalysis}`);
  }
  if (result.englishAnalysis) {
    lines.push(`  english analysis: ${result.englishAnalysis}`);
  }

  lines.push('');
  return lines.join('\n');
}
