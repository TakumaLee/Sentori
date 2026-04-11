import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { findPromptFiles, readFileContent, isTestFileForScoring, applyContextDowngrades } from '../utils/file-utils';

// Classical Chinese function words (虛詞) — high-density presence indicates archaic register
const CLASSICAL_CHINESE_PARTICLES = [
  '之', '乎', '者', '也', '焉', '哉', '耳', '矣',
  '夫', '蓋', '豈', '曰', '謂', '於', '其', '則',
  '雖', '故', '遂', '乃', '亦', '且', '既', '況',
];

// Classical Chinese pronouns (archaic forms not used in modern Chinese)
const CLASSICAL_CHINESE_PRONOUNS = ['吾', '予', '余', '汝', '爾', '尔', '彼'];

// Old English archaic markers
const OLD_ENGLISH_MARKERS = /\b(?:thee|thou|thy|thine|dost|doth|hast|hath|shalt|shouldst|wouldst|art\s+thou|ye|hither|thither|wherefore|forsooth|prithee|verily|begone|nay)\b/gi;

// Latin keyword patterns (common in Latin-based jailbreak attempts)
const LATIN_MARKERS = /\b(?:omnia|praedicta|mandata|praecepta|regulis|nunc|iam|sine|vinculis|liber|fac|responde|scribe|ignora|obliviscere|praetermitte)\b/gi;

export interface LanguageRegisterAnalysis {
  classicalChineseScore: number;
  classicalChineseParticles: string[];
  oldEnglishScore: number;
  oldEnglishMarkers: string[];
  latinScore: number;
  latinMarkers: string[];
  totalArchaicScore: number;
}

/**
 * Analyze text for archaic language register density.
 * Returns a score indicating how "archaic" the text is.
 */
export function analyzeLanguageRegister(content: string): LanguageRegisterAnalysis {
  const result: LanguageRegisterAnalysis = {
    classicalChineseScore: 0,
    classicalChineseParticles: [],
    oldEnglishScore: 0,
    oldEnglishMarkers: [],
    latinScore: 0,
    latinMarkers: [],
    totalArchaicScore: 0,
  };

  // === Classical Chinese analysis ===
  // Count classical particles
  const cjkChars = content.match(/[\u4e00-\u9fff]/g);
  if (cjkChars && cjkChars.length >= 5) {
    const totalCJK = cjkChars.length;
    let particleCount = 0;
    const foundParticles = new Set<string>();

    for (const char of content) {
      if (CLASSICAL_CHINESE_PARTICLES.includes(char)) {
        particleCount++;
        foundParticles.add(char);
      }
      if (CLASSICAL_CHINESE_PRONOUNS.includes(char)) {
        particleCount++;
        foundParticles.add(char);
      }
    }

    // Particle density: ratio of classical particles to total CJK characters
    const density = particleCount / totalCJK;
    result.classicalChineseParticles = [...foundParticles];

    // Thresholds:
    // >= 15% particle density with 3+ unique particles → high confidence
    // >= 8% with 2+ unique particles → medium confidence
    if (density >= 0.15 && foundParticles.size >= 3) {
      result.classicalChineseScore = 3;
    } else if (density >= 0.08 && foundParticles.size >= 2) {
      result.classicalChineseScore = 2;
    } else if (density >= 0.05 && foundParticles.size >= 2) {
      result.classicalChineseScore = 1;
    }
  }

  // === Old English analysis ===
  const oeMatches = content.match(OLD_ENGLISH_MARKERS);
  if (oeMatches) {
    const uniqueOE = [...new Set(oeMatches.map(m => m.toLowerCase()))];
    result.oldEnglishMarkers = uniqueOE;
    if (uniqueOE.length >= 4) {
      result.oldEnglishScore = 3;
    } else if (uniqueOE.length >= 2) {
      result.oldEnglishScore = 2;
    } else {
      result.oldEnglishScore = 1;
    }
  }

  // === Latin analysis ===
  const latinMatches = content.match(LATIN_MARKERS);
  if (latinMatches) {
    const uniqueLatin = [...new Set(latinMatches.map(m => m.toLowerCase()))];
    result.latinMarkers = uniqueLatin;
    if (uniqueLatin.length >= 4) {
      result.latinScore = 3;
    } else if (uniqueLatin.length >= 2) {
      result.latinScore = 2;
    } else {
      result.latinScore = 1;
    }
  }

  result.totalArchaicScore = result.classicalChineseScore + result.oldEnglishScore + result.latinScore;
  return result;
}

/**
 * Generate findings from language register analysis.
 */
export function generateRegisterFindings(
  analysis: LanguageRegisterAnalysis,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];

  if (analysis.classicalChineseScore >= 2) {
    findings.push({
      id: `LR-001-${filePath}`,
      scanner: 'Language Register Scanner',
      severity: analysis.classicalChineseScore >= 3 ? 'high' : 'medium',
      title: 'Classical Chinese register detected',
      description: `High density of Classical Chinese particles (${analysis.classicalChineseParticles.join(', ')}) detected. Classical Chinese (文言文) can be used to bypass LLM safety filters (CC-BOS attack). Review this content for potential archaic language jailbreak attempts.`,
      file: filePath,
      recommendation: 'Add archaic language detection to your input processing pipeline. Consider normalizing Classical Chinese input to modern Chinese before LLM processing, or explicitly reject Classical Chinese prompts in your system instructions.',
      confidence: analysis.classicalChineseScore >= 3 ? 'likely' : 'possible',
    });
  }

  if (analysis.oldEnglishScore >= 2) {
    findings.push({
      id: `LR-002-${filePath}`,
      scanner: 'Language Register Scanner',
      severity: analysis.oldEnglishScore >= 3 ? 'high' : 'medium',
      title: 'Old English register detected',
      description: `Old English archaic markers detected (${analysis.oldEnglishMarkers.join(', ')}). Archaic English can be used to bypass LLM safety filters. Review for potential jailbreak attempts using archaic language registers.`,
      file: filePath,
      recommendation: 'Add language register detection for Old English patterns. Consider normalizing archaic English to modern English before processing.',
      confidence: analysis.oldEnglishScore >= 3 ? 'likely' : 'possible',
    });
  }

  if (analysis.latinScore >= 2) {
    findings.push({
      id: `LR-003-${filePath}`,
      scanner: 'Language Register Scanner',
      severity: analysis.latinScore >= 3 ? 'high' : 'medium',
      title: 'Latin language register detected',
      description: `Latin keywords detected (${analysis.latinMarkers.join(', ')}). Latin can be used to bypass LLM safety filters. Review for potential jailbreak attempts using Latin language.`,
      file: filePath,
      recommendation: 'Add language register detection for Latin input patterns. Consider rejecting or flagging prompts with high Latin content density.',
      confidence: analysis.latinScore >= 3 ? 'likely' : 'possible',
    });
  }

  // Cross-register: multiple archaic languages in same content → higher suspicion
  if (analysis.totalArchaicScore >= 4) {
    const registers: string[] = [];
    if (analysis.classicalChineseScore > 0) registers.push('Classical Chinese');
    if (analysis.oldEnglishScore > 0) registers.push('Old English');
    if (analysis.latinScore > 0) registers.push('Latin');

    if (registers.length >= 2) {
      findings.push({
        id: `LR-004-${filePath}`,
        scanner: 'Language Register Scanner',
        severity: 'critical',
        title: 'Multiple archaic language registers detected',
        description: `Multiple archaic language registers detected in the same content (${registers.join(', ')}). This is a strong indicator of a cross-lingual jailbreak attempt combining multiple archaic languages to bypass safety filters.`,
        file: filePath,
        recommendation: 'This content exhibits cross-lingual archaic language patterns. Implement multi-register language detection and reject or normalize mixed-archaic inputs.',
        confidence: 'likely',
      });
    }
  }

  return findings;
}

export const languageRegisterScanner: ScannerModule = {
  name: 'Language Register Scanner',
  description: 'Detects archaic/classical language registers (Classical Chinese, Latin, Old English) that may be used to bypass LLM safety filters (CC-BOS attacks)',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const analysis = analyzeLanguageRegister(content);

        if (analysis.totalArchaicScore >= 2) {
          const fileFindings = generateRegisterFindings(analysis, file);
          applyContextDowngrades(fileFindings, file);

          if (isTestFileForScoring(file)) {
            for (const f of fileFindings) {
              f.isTestFile = true;
              if (f.title && !f.title.startsWith('[TEST]')) {
                f.title = `[TEST] ${f.title}`;
              }
            }
          }

          findings.push(...fileFindings);
        }
      } catch {
        // Skip unreadable files
      }
    }

    return {
      scanner: 'Language Register Scanner',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};
