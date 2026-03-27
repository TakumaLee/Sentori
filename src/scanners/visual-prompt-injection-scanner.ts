import { Scanner, ScanResult, Finding, Severity, ScannerOptions } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';
import { INJECTION_PATTERNS } from '../patterns/injection-patterns';
import { shouldIgnoreFile } from '../utils/ignore-parser';
import * as fs from 'fs';
import * as path from 'path';

// Dynamic import for tesseract.js (ESM module)
let Tesseract: any = null;

async function getTesseract() {
  if (!Tesseract) {
    Tesseract = await import('tesseract.js');
  }
  return Tesseract;
}

export class VisualPromptInjectionScanner implements Scanner {
  name = 'Visual Prompt Injection Scanner';
  description = 'Detects suspicious image processing + LLM vision API combinations and scans image files for embedded prompt injection text';

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    let scannedFiles = 0;

    // Scan code files
    for (const file of walkFiles(targetPath, { includeVendored: options?.includeVendored, exclude: options?.exclude, sentoriIgnorePatterns: options?.sentoriIgnorePatterns })) {
      if (this.isCodeFile(file.path)) {
        scannedFiles++;
        const codeFindings = this.scanFile(file);
        findings.push(...codeFindings);
      }
    }

    // Scan image files only in deep-scan mode (OCR is slow)
    const imageFiles = this.findImageFiles(targetPath, options?.exclude, options?.sentoriIgnorePatterns);
    if (!process.env.SENTORI_DEEP_SCAN) {
      // Without OCR, emit one INFO summary instead of per-image findings
      if (imageFiles.length > 0) {
        findings.push({
          id: 'VPI-IMG-SUMMARY',
          scanner: 'visual-prompt-injection-scanner',
          severity: 'info',
          title: `${imageFiles.length} image file(s) found — OCR not enabled`,
          description: `Found ${imageFiles.length} image file(s) that may contain embedded prompt injection. Enable --deep-scan to perform OCR analysis.`,
          file: targetPath,
          confidence: 'possible',
          recommendation: 'Run with --deep-scan to enable OCR-based visual prompt injection detection.',
        });
      }
      return {
        scanner: this.name,
        findings,
        scannedFiles,
        duration: Date.now() - start,
      };
    }


    for (const imagePath of imageFiles) {
      scannedFiles++;
      const imageFindings = await this.scanImageFile({ path: imagePath, relativePath: path.relative(targetPath, imagePath), content: '' });
      findings.push(...imageFindings);
    }

    return {
      scanner: this.name,
      findings,
      scannedFiles,
      duration: Date.now() - start,
    };
  }

  /**
   * Find all image files in directory, respecting exclude and sentoriIgnore patterns.
   */
  private findImageFiles(dir: string, exclude?: string[], sentoriIgnorePatterns?: string[]): string[] {
    const imageFiles: string[] = [];
    const allExcludePatterns = [...(exclude ?? []), ...(sentoriIgnorePatterns ?? [])];

    const skipDirs = new Set([
      'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
      'browser', 'Extensions', '.cache', 'Cache', 'CacheStorage',
      'GPUCache', 'ShaderCache', 'GrShaderCache', '__pycache__',
      '.venv', 'venv', '.tox', '.mypy_cache',
      'models', 'checkpoints', 'weights', 'sd-setup',
      // Runtime data directories (sync with file-walker.ts skipDirs)
      'outputs', 'output', 'data', 'logs', 'dbs',
      'vault', 'uploads', 'history', 'runtime',
      // Agent workstation runtime directories
      'sessions', 'cache', 'media', 'user-data',
      'snapshots', 'crawl', 'scraped', 'downloaded',
      'cron-runs',
    ]);

    const walk = (currentDir: string): void => {
      if (!fs.existsSync(currentDir)) return;
      try {
        const items = fs.readdirSync(currentDir, { withFileTypes: true });
        for (const item of items) {
          const fullPath = path.join(currentDir, item.name);
          if (item.isDirectory()) {
            if (skipDirs.has(item.name)) continue;
            // Check user-supplied exclude patterns for directories
            if (allExcludePatterns.length > 0) {
              const relDir = path.relative(dir, fullPath);
              if (shouldIgnoreFile(relDir + '/x', allExcludePatterns)) continue;
            }
            walk(fullPath);
          } else if (item.isFile()) {
            const ext = path.extname(item.name).toLowerCase();
            if (['.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp'].includes(ext)) {
              // Check user-supplied exclude patterns for files
              if (allExcludePatterns.length > 0) {
                const relFile = path.relative(dir, fullPath);
                if (shouldIgnoreFile(relFile, allExcludePatterns)) continue;
              }
              imageFiles.push(fullPath);
            }
          }
        }
      } catch {
        // skip unreadable directories
      }
    };

    walk(dir);
    return imageFiles;
  }

  private isCodeFile(filePath: string): boolean {
    return /\.(ts|js|tsx|jsx|py|go|rs|java)$/.test(filePath);
  }

  private isImageFile(filePath: string): boolean {
    return /\.(jpg|jpeg|png|webp|gif|bmp)$/i.test(filePath);
  }

  /**
   * PI-150: Scan image files for embedded prompt injection text using OCR
   */
  private async scanImageFile(file: FileEntry): Promise<Finding[]> {
    const findings: Finding[] = [];
    const filePath = file.path;

    try {
      // Check if file exists and is readable
      if (!fs.existsSync(filePath)) {
        return findings;
      }

      const stat = fs.statSync(filePath);
      if (stat.size > 10 * 1024 * 1024) {
        // Skip large images (> 10MB) to avoid timeout
        return findings;
      }

      // Skip GIF files - multi-frame GIFs cause tesseract to hang
      const ext = path.extname(filePath).toLowerCase();
      if (ext === '.gif') {
        return findings;
      }

      // Perform OCR on image with timeout
      const tesseract = await getTesseract();
      const worker = await tesseract.createWorker('eng', undefined, {
        logger: () => {}, // Disable logging to reduce noise
      });
      
      const ocrTimeout = 30000; // 30 second timeout per image
      const recognizePromise = worker.recognize(filePath);
      const timeoutPromise = new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('OCR timeout')), ocrTimeout)
      );
      
      let text: string;
      try {
        const result = await Promise.race([recognizePromise, timeoutPromise]);
        text = (result as any).data.text;
      } catch (e) {
        await worker.terminate();
        return findings;
      }
      await worker.terminate();

      if (!text || text.trim().length === 0) {
        // No text detected in image
        return findings;
      }

      // Check for injection patterns in extracted text
      const detectedPatterns = this.detectInjectionPatterns(text);

      if (detectedPatterns.length > 0) {
        const severityMap: { [key: string]: number } = {
          critical: 3,
          high: 2,
          medium: 1,
          info: 0,
        };

        // Sort by severity (highest first)
        detectedPatterns.sort((a, b) => severityMap[b.severity] - severityMap[a.severity]);

        // Report the top 3 most severe patterns found
        const topPatterns = detectedPatterns.slice(0, 3);

        for (const pattern of topPatterns) {
          findings.push({
            id: `VPI-150-${pattern.id}-${path.basename(filePath)}`,
            scanner: 'visual-prompt-injection-scanner',
            severity: pattern.severity,
            title: `Visual Prompt Injection Detected: ${pattern.category}`,
            description: `Image contains suspicious text that matches prompt injection pattern "${pattern.description}". This could be a visual prompt injection attack where malicious instructions are embedded in images. Extracted text snippet: "${text.substring(0, 150)}..."`,
            file: filePath,
            evidence: `Pattern: ${pattern.id} (${pattern.category})\nMatched text: ${text.substring(0, 300)}`,
            confidence: 'likely',
            recommendation: 'Review image content manually. If this image is processed by vision models, implement: 1) OCR-based text extraction and sanitization, 2) Pattern-based prompt injection detection before sending to vision API, 3) Content moderation, 4) Image provenance verification',
          });
        }
      }

    } catch (error) {
      // OCR failed - silently skip (common for test files with fake image content)
      // Only report for actual image processing errors in production use
      const errorMsg = error instanceof Error ? error.message : String(error);
      
      // Ignore common test/fake image errors
      const ignoredErrors = [
        'Invalid file type',
        'unsupported image format',
        'pix not read',
        'cannot be read',
        'Error attempting to read image',
        'Unknown format'
      ];
      
      const shouldIgnore = ignoredErrors.some(msg => errorMsg.includes(msg));
      
      if (!shouldIgnore) {
        findings.push({
          id: `VPI-150-OCR-ERROR-${path.basename(filePath)}`,
          scanner: 'visual-prompt-injection-scanner',
          severity: 'info',
          title: 'Image OCR Processing Failed',
          description: `Failed to perform OCR on image file: ${errorMsg}`,
          file: filePath,
          confidence: 'possible',
          recommendation: 'Ensure image format is supported and file is not corrupted. Supported formats: JPG, PNG, WebP',
        });
      }
    }

    return findings;
  }

  /**
   * Detect injection patterns in text extracted from images
   */
  private detectInjectionPatterns(text: string): Array<{ id: string; severity: Severity; category: string; description: string }> {
    const detected: Array<{ id: string; severity: Severity; category: string; description: string }> = [];

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.pattern.test(text)) {
        detected.push({
          id: pattern.id,
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
        });
      }
    }

    return detected;
  }

  private scanFile(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const content = file.content;
    const filePath = file.path;

    // Pattern 1: Vision API usage without input validation
    findings.push(...this.detectVisionAPIUsage(content, filePath));

    // Pattern 2: Image processing with external sources
    findings.push(...this.detectUnsafeImageSources(content, filePath));

    // Pattern 3: Missing content moderation on vision inputs
    findings.push(...this.detectMissingModeration(content, filePath));

    return findings;
  }

  private detectVisionAPIUsage(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Vision API patterns
    const visionAPIs = [
      { pattern: /openai.*vision|gpt-4.*vision/i, api: 'OpenAI GPT-4 Vision' },
      { pattern: /anthropic.*vision|claude.*vision|anthropic.*messages.*create.*image|claude.*\d+.*opus|claude.*\d+.*sonnet/i, api: 'Anthropic Claude Vision' },
      { pattern: /gemini.*vision|google.*vision/i, api: 'Google Gemini Vision' },
      { pattern: /llava|blip|clip/i, api: 'Open Source Vision Model' },
      { pattern: /vision.*api|image.*analyze|ocr.*api/i, api: 'Generic Vision API' },
    ];

    // Validation patterns (good practices)
    // Exclude lines that start with // or are inside /* */ comments
    const codeWithoutComments = content.split('\n')
      .filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*'))
      .join('\n')
      .replace(/\/\*[\s\S]*?\*\//g, '');
    
    const validationPatterns = [
      /sanitize.*image|validate.*image|check.*image/i,
      /content.*moderation|safety.*filter/i,
      /image.*hash|image.*signature/i,
      /whitelist|allowlist|trusted.*source/i,
    ];

    const hasValidation = validationPatterns.some(p => p.test(codeWithoutComments));

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, api } of visionAPIs) {
        if (pattern.test(line)) {
          const severity: Severity = hasValidation ? 'medium' : 'high';
          const id = `VPI-001-${filePath}-${i + 1}`;

          if (!findings.some(f => f.id === id)) {
            findings.push({
              id,
              scanner: 'visual-prompt-injection-scanner',
              severity,
              title: `Visual Prompt Injection Risk: ${api} without validation`,
              description: `Detected ${api} usage. ${hasValidation ? 'Some validation exists but verify it covers visual prompt injection.' : 'No input validation detected for image content.'} Line: "${line.trim().substring(0, 100)}"`,
              file: filePath,
              line: i + 1,
              confidence: hasValidation ? 'possible' : 'likely',
              recommendation: 'Implement image content validation: 1) Hash-based verification for trusted sources, 2) Content moderation API, 3) Strip embedded text/metadata from images, 4) Rate limiting per user/source',
            });
          }
        }
      }
    }

    return findings;
  }

  private detectUnsafeImageSources(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Patterns for loading images from untrusted sources
    const unsafeSourcePatterns = [
      { pattern: /fetch\s*\(|download.*image|http.*image|imageResponse|image.*fetch/i, source: 'HTTP fetch' },
      { pattern: /user.*upload|file.*upload|multipart/i, source: 'User upload' },
      { pattern: /url.*param|query.*image|request.*image/i, source: 'URL parameter' },
      { pattern: /s3.*get|blob.*download|storage.*read/i, source: 'Cloud storage' },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, source } of unsafeSourcePatterns) {
        if (pattern.test(line)) {
          // Check if this line is near vision API usage (within 20 lines)
          const nearbyLines = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
          const hasVisionAPI = /vision|gpt-4|claude|gemini|analyze.*image/i.test(nearbyLines);

          if (hasVisionAPI) {
            const id = `VPI-002-${filePath}-${i + 1}`;
            if (!findings.some(f => f.id === id)) {
              findings.push({
                id,
                scanner: 'visual-prompt-injection-scanner',
                severity: 'high',
                title: `Unsafe Image Source: ${source} + Vision API`,
                description: `Images from ${source} processed by vision model without apparent validation. Attackers can inject instructions via steganography, embedded text, or OCR-readable content. Line: "${line.trim().substring(0, 100)}"`,
                file: filePath,
                line: i + 1,
                confidence: 'likely',
                recommendation: 'Validate image sources: 1) Accept only from trusted domains/users, 2) Re-encode/sanitize images before processing, 3) Strip EXIF and metadata, 4) Implement content hash verification',
              });
            }
          }
        }
      }
    }

    return findings;
  }

  private detectMissingModeration(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Check if vision API exists but no moderation
    const hasVisionAPI = /vision|gpt-4.*vision|claude.*vision|analyze.*image/i.test(content);
    const hasModerationAPI = /\.moderations?\.create|moderations?\.create|perspective.*api\.analyze|rekognition\.detect/i.test(content);
    const hasTextExtraction = /ocr|tesseract|text.*from.*image|extract.*text/i.test(content);

    if (hasVisionAPI && !hasModerationAPI) {
      // Find the first vision API usage line
      for (let i = 0; i < lines.length; i++) {
        if (/vision|analyze.*image|process.*image/i.test(lines[i])) {
          const id = `VPI-003-${filePath}-${i + 1}`;
          if (!findings.some(f => f.id === id)) {
            findings.push({
              id,
              scanner: 'visual-prompt-injection-scanner',
              severity: 'medium',
              title: 'Missing Content Moderation for Vision Input',
              description: `Vision API usage detected without content moderation. ${hasTextExtraction ? 'Text extraction present - verify OCR output is sanitized.' : ''} Malicious images can contain hidden instructions readable by vision models but invisible to humans.`,
              file: filePath,
              line: i + 1,
              confidence: 'likely',
              recommendation: 'Add content moderation: 1) Use moderation API (OpenAI Moderation, Perspective API), 2) Sanitize extracted text for prompt injection patterns, 3) Implement image hashing to detect known malicious images',
            });
          }
          break; // Only report once per file
        }
      }
    }

    return findings;
  }
}
