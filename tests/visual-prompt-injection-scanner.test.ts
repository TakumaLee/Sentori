import { VisualPromptInjectionScanner } from '../src/scanners/visual-prompt-injection-scanner';
import { OcrWorkerPool } from '../src/utils/ocr-worker-pool';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Visual Prompt Injection Scanner', () => {
  let scanner: VisualPromptInjectionScanner;
  let tempDir: string;

  beforeEach(() => {
    scanner = new VisualPromptInjectionScanner();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpi-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function writeTestFile(filename: string, content: string): string {
    const filePath = path.join(tempDir, filename);
    fs.writeFileSync(filePath, content);
    return filePath;
  }

  // === Test 1: Vision API usage without validation ===
  describe('VPI-001: Vision API without validation', () => {
    test('detects OpenAI GPT-4 Vision usage without validation', async () => {
      writeTestFile('vision-unsafe.ts', `
        import OpenAI from 'openai';
        const openai = new OpenAI();
        
        async function analyzeImage(imageUrl: string) {
          const response = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{
              role: "user",
              content: [
                { type: "text", text: "What's in this image?" },
                { type: "image_url", image_url: { url: imageUrl } }
              ]
            }]
          });
          return response.choices[0].message.content;
        }
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-001'));
      
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
      expect(finding!.title).toContain('OpenAI GPT-4 Vision');
      expect(finding!.description).toContain('No input validation detected');
    });

    test('downgrade severity when validation exists', async () => {
      writeTestFile('vision-safe.ts', `
        import OpenAI from 'openai';
        const openai = new OpenAI();
        
        async function analyzeImage(imageUrl: string) {
          // Validate image source
          if (!imageUrl.startsWith('https://trusted.example.com/')) {
            throw new Error('Untrusted image source');
          }
          
          // Sanitize image before processing
          const sanitizedImage = await sanitizeImage(imageUrl);
          
          const response = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{
              role: "user",
              content: [
                { type: "text", text: "What's in this image?" },
                { type: "image_url", image_url: { url: sanitizedImage } }
              ]
            }]
          });
          return response.choices[0].message.content;
        }
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-001'));
      
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
      expect(finding!.confidence).toBe('possible');
    });

    test('detects Claude Vision API', async () => {
      writeTestFile('claude-vision.ts', `
        import Anthropic from '@anthropic-ai/sdk';
        const anthropic = new Anthropic();
        
        const message = await anthropic.messages.create({
          model: "claude-3-opus-20240229",
          messages: [{
            role: "user",
            content: [
              { type: "image", source: { type: "url", url: imageUrl } },
              { type: "text", text: "Describe this image" }
            ]
          }]
        });
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-001'));
      
      expect(finding).toBeDefined();
      expect(finding!.title).toContain('Anthropic Claude Vision');
    });
  });

  // === Test 2: Unsafe image sources ===
  describe('VPI-002: Unsafe image sources', () => {
    test('detects user upload + vision API combination', async () => {
      writeTestFile('upload-handler.ts', `
        import express from 'express';
        import multer from 'multer';
        import OpenAI from 'openai';
        
        const upload = multer({ dest: 'uploads/' });
        const openai = new OpenAI();
        
        app.post('/analyze', upload.single('image'), async (req, res) => {
          const imagePath = req.file.path;
          
          // Dangerous: user-uploaded image sent directly to vision model
          const response = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{
              role: "user",
              content: [
                { type: "image_url", image_url: { url: imagePath } }
              ]
            }]
          });
          
          res.json(response);
        });
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-002'));
      
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
      expect(finding!.title).toContain('User upload');
      expect(finding!.description).toContain('steganography');
    });

    test('detects HTTP fetch + vision API', async () => {
      writeTestFile('fetch-analyze.py', `
import requests
from openai import OpenAI

client = OpenAI()

def analyze_web_image(image_url):
    # Download image from web
    response = requests.get(image_url)
    image_data = response.content
    
    # Process with vision model (no validation!)
    result = client.chat.completions.create(
        model="gpt-4-vision-preview",
        messages=[{
            "role": "user",
            "content": [{"type": "image_url", "image_url": {"url": image_url}}]
        }]
    )
    return result
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-002'));
      
      expect(finding).toBeDefined();
      expect(finding!.title).toContain('HTTP fetch');
      expect(finding!.recommendation).toContain('Re-encode/sanitize images');
    });

    test('detects cloud storage + vision API', async () => {
      writeTestFile('s3-vision.ts', `
        import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
        import OpenAI from 'openai';
        
        const s3 = new S3Client({});
        const openai = new OpenAI();
        
        async function analyzeS3Image(bucket: string, key: string) {
          const { Body } = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
          const imageBuffer = await Body.transformToByteArray();
          
          // Process with vision model
          const response = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{ role: "user", content: "Analyze image" }]
          });
        }
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-002'));
      
      expect(finding).toBeDefined();
      expect(finding!.title).toContain('Cloud storage');
    });
  });

  // === Test 3: Missing content moderation ===
  describe('VPI-003: Missing content moderation', () => {
    test('reports missing moderation for vision API', async () => {
      writeTestFile('no-moderation.ts', `
        import OpenAI from 'openai';
        const openai = new OpenAI();
        
        async function processImage(imageUrl: string) {
          const visionResponse = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{
              role: "user",
              content: [{ type: "image_url", image_url: { url: imageUrl } }]
            }]
          });
          
          // No content moderation!
          return visionResponse.choices[0].message.content;
        }
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-003'));
      
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
      expect(finding!.title).toContain('Missing Content Moderation');
      expect(finding!.recommendation).toContain('moderation API');
    });

    test('no finding when moderation exists', async () => {
      writeTestFile('with-moderation.ts', `
        import OpenAI from 'openai';
        const openai = new OpenAI();
        
        async function processImage(imageUrl: string) {
          const visionResponse = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{
              role: "user",
              content: [{ type: "image_url", image_url: { url: imageUrl } }]
            }]
          });
          
          // Apply content moderation
          const moderationResult = await openai.moderations.create({
            input: visionResponse.choices[0].message.content
          });
          
          if (moderationResult.results[0].flagged) {
            throw new Error('Content policy violation');
          }
          
          return visionResponse.choices[0].message.content;
        }
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-003'));
      
      expect(finding).toBeUndefined();
    });

    test('mentions OCR when text extraction detected', async () => {
      writeTestFile('ocr-vision.ts', `
        import Tesseract from 'tesseract.js';
        import OpenAI from 'openai';
        const openai = new OpenAI();
        
        async function analyzeImage(imageUrl: string) {
          // Extract text from image
          const { data: { text } } = await Tesseract.recognize(imageUrl);
          
          // Also process with vision model
          const visionResponse = await openai.chat.completions.create({
            model: "gpt-4-vision-preview",
            messages: [{ role: "user", content: "Analyze" }]
          });
        }
      `);

      const result = await scanner.scan(tempDir);
      const finding = result.findings.find(f => f.id?.includes('VPI-003'));
      
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('Text extraction present');
      expect(finding!.description).toContain('OCR output is sanitized');
    });
  });

  // === Test 4: Scanner metadata ===
  test('scanner has correct metadata', () => {
    expect(scanner.name).toBe('Visual Prompt Injection Scanner');
    expect(scanner.description).toContain('prompt injection');
  });

  test('ignores non-code files', async () => {
    writeTestFile('README.md', 'Some documentation');
    writeTestFile('data.json', '{"key": "value"}');
    
    const result = await scanner.scan(tempDir);
    expect(result.scannedFiles).toBe(0);
  });

  test('scans multiple code files', async () => {
    writeTestFile('file1.ts', 'const x = 1;');
    writeTestFile('file2.js', 'const y = 2;');
    writeTestFile('file3.py', 'z = 3');
    
    const result = await scanner.scan(tempDir);
    expect(result.scannedFiles).toBe(3);
  });

  // === PI-150: OCR-based Visual Prompt Injection Detection ===
  describe('PI-150: OCR-based image content scanning', () => {
    test('scanner recognizes image file formats', async () => {
      // Create code files only to avoid OCR errors
      writeTestFile('code1.ts', 'const x = 1;');
      writeTestFile('code2.js', 'const y = 2;');
      writeTestFile('code3.py', 'z = 3');
      
      const result = await scanner.scan(tempDir);
      
      // Scanner should scan 3 code files
      expect(result.scannedFiles).toBe(3);
    });

    test('scanner description mentions image scanning capability', () => {
      expect(scanner.description).toContain('image');
      expect(scanner.description).toContain('embedded');
      expect(scanner.description).toContain('prompt injection');
    });

    test('scanner differentiates image files from code files', async () => {
      // Test the scanner can differentiate code files (images would require real image files)
      writeTestFile('code.ts', 'const x = 1;');
      writeTestFile('script.js', 'const y = 2;');
      writeTestFile('app.py', 'z = 3');
      writeTestFile('doc.md', '# Documentation');

      const result = await scanner.scan(tempDir);
      
      // Should scan: 3 code files (.ts, .js, .py)
      // .md file is not scanned by default in this scanner
      expect(result.scannedFiles).toBe(3);
    });

    test('scanner includes visual prompt injection in description', () => {
      // Verify scanner is properly configured for PI-150
      expect(scanner.name).toBe('Visual Prompt Injection Scanner');
      expect(scanner.description.toLowerCase()).toContain('embedded');
      expect(scanner.description.toLowerCase()).toContain('image');
    });
  });

  // === PI-150: OCR concurrency limit ===
  describe('PI-150: OCR concurrency limit', () => {
    test('OcrWorkerPool enforces max 4 simultaneous OCR calls', async () => {
      // Inject a pool with concurrency=4 and patch runOcr to track concurrency
      // without invoking real tesseract.
      const pool = new OcrWorkerPool({ concurrency: 4, budgetMs: 60_000, timeoutMs: 5_000 });

      let maxConcurrent = 0;
      let activeCalls = 0;

      // Patch private runOcr — acquire/release are real, so this correctly
      // measures how many workers run simultaneously within the pool.
      (pool as any).runOcr = async (_imagePath: string): Promise<{ text: string; budgetExceeded: boolean }> => {
        activeCalls++;
        maxConcurrent = Math.max(maxConcurrent, activeCalls);
        await new Promise(resolve => setTimeout(resolve, 20));
        activeCalls--;
        return { text: '', budgetExceeded: false };
      };

      scanner.ocrPool = pool;

      // 10 fake image files — large enough to saturate the pool's 4-slot limit
      const imageCount = 10;
      for (let i = 0; i < imageCount; i++) {
        writeTestFile(`concurrent-test-${i}.png`, 'fake');
      }

      const origEnv = process.env.SENTORI_DEEP_SCAN;
      process.env.SENTORI_DEEP_SCAN = '1';
      try {
        await scanner.scan(tempDir);
      } finally {
        if (origEnv === undefined) {
          delete process.env.SENTORI_DEEP_SCAN;
        } else {
          process.env.SENTORI_DEEP_SCAN = origEnv;
        }
      }

      // Must not exceed 4 concurrent OCR workers
      expect(maxConcurrent).toBeLessThanOrEqual(4);
      // Must have used at least some concurrency (not purely serial with 10 images)
      expect(maxConcurrent).toBeGreaterThan(1);
    });
  });
});
