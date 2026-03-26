import * as path from 'path';
import * as fs from 'fs';
import * as readline from 'readline';
import { ScannerModule, ScanResult, Finding, Severity, ScannerOptions } from '../types';
import { findPromptFiles, findConfigFiles, findFiles, isTestOrDocFile, isTestFileForScoring } from '../utils/file-utils';

export interface ChannelDefinition {
  id: string;
  name: string;
  /** Keywords that indicate this channel is used */
  detectPatterns: RegExp[];
  /**
   * Code-level evidence patterns that confirm actual integration (imports,
   * config, API calls). If set, the channel is only confirmed when BOTH a
   * detectPattern matches AND a codeEvidencePattern matches in source files.
   * Without code evidence the finding is downgraded to info.
   */
  codeEvidencePatterns?: RegExp[];
  /** Defense patterns that should exist if this channel is active */
  defensePatterns: { pattern: RegExp; desc: string }[];
  /** Minimum defenses needed for "partial" */
  partialThreshold: number;
  /** Minimum defenses needed for "full" */
  fullThreshold: number;
  /** Override undefended severity (default: high) */
  undefendedSeverity?: Severity;
}

const CHANNEL_DEFINITIONS: ChannelDefinition[] = [
  {
    id: 'CH-EMAIL',
    name: 'Email/Gmail',
    detectPatterns: [
      /\bgmail\b/i,
      /\bemail\b/i,
      /\bsmtp\b/i,
      /\bmail\.google\b/i,
      /\bsendEmail\b/i,
      /\breadEmail\b/i,
      /\bmailgun\b/i,
      /\bsendgrid\b/i,
      /\b(?:aws[_-]?)?ses\b/i,
      /\bnodemailer\b/i,
      /\bpostmark\b/i,
    ],
    defensePatterns: [
      { pattern: /(?:外部|external)\s*(?:email|mail).*(?:純文字|plain\s*text)/i, desc: 'treat external email as plain text' },
      { pattern: /email.*(?:純文字|plain\s*text)|(?:純文字|plain\s*text).*email/i, desc: 'email content is plain text' },
      { pattern: /email.*(?:內容|content).*(?:不執行|do\s*not\s*execute)/i, desc: 'do not execute email content' },
      { pattern: /(?:不同|different).*(?:通道|channel).*(?:不同|different).*(?:信任|trust)/i, desc: 'different trust levels per channel' },
      { pattern: /(?:channel|通道).*(?:trust\s+)?(?:boundary|邊界|level|等級)/i, desc: 'channel trust boundaries' },
      { pattern: /email.*(?:不是|不等於|≠).*(?:telegram|verified)/i, desc: 'email ≠ verified channel' },
      { pattern: /(?:不執行|ignore).*(?:email|mail).*(?:指令|instruction|command)/i, desc: 'ignore email instructions' },
    ],
    partialThreshold: 1,
    fullThreshold: 3,
  },
  {
    id: 'CH-SOCIAL',
    name: 'Social Media (X/Twitter)',
    detectPatterns: [
      /\btwitter\b/i,
      /\bx\.com\b/i,
      /\btweet\b/i,
      /\bpostTweet\b/i,
      /(?:^|\s)@\w{1,15}\b/,
    ],
    codeEvidencePatterns: [
      /(?:require|import)\s*.*twitter/i,
      /(?:require|import)\s*.*twit\b/i,
      /new\s+Twitter/i,
      /twitter[_-]?api/i,
      /postTweet\s*\(/i,
      /TWITTER_(?:API|BEARER|ACCESS)/i,
    ],
    defensePatterns: [
      { pattern: /(?:發文|post|tweet).*(?:前|before).*(?:確認|confirm)/i, desc: 'confirm before posting' },
      { pattern: /(?:不|do\s*not|never).*(?:洩漏|leak|disclose|share).*(?:私人|private|personal)/i, desc: 'no private info disclosure' },
      { pattern: /anti[_-]?manipulation/i, desc: 'anti-manipulation rules' },
      { pattern: /(?:social\s*media|twitter|tweet).*(?:confirm|approval|review)/i, desc: 'social media approval flow' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-TELEGRAM',
    name: 'Telegram',
    detectPatterns: [
      /\btelegram\b/i,
      /\bbot_token\b/i,
      /\bsendMessage\b/i,
      /\bTelegramBot\b/i,
    ],
    defensePatterns: [
      { pattern: /(?:只|only).*(?:接受|accept).*(?:telegram|特定|specific).*(?:id|user)/i, desc: 'accept only specific Telegram user' },
      { pattern: /telegram.*(?:id|user_?id)\s*[:=]\s*\d+/i, desc: 'Telegram user ID verification' },
      { pattern: /(?:verify|驗證).*(?:telegram|sender|發送者)/i, desc: 'verify Telegram sender' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-DISCORD',
    name: 'Discord',
    detectPatterns: [
      /\bdiscord\b/i,
      /\bwebhook\b/i,
      /\bDiscordClient\b/i,
    ],
    codeEvidencePatterns: [
      /(?:require|import)\s*.*discord\.js/i,
      /(?:require|import)\s*.*discord/i,
      /new\s+(?:Client|Discord)/i,
      /DISCORD_(?:TOKEN|BOT|WEBHOOK)/i,
      /discord\.(?:js|py)/i,
    ],
    defensePatterns: [
      { pattern: /(?:discord|webhook).*(?:verify|auth|permission)/i, desc: 'Discord auth/permission check' },
      { pattern: /(?:role|permission).*(?:check|verify|require)/i, desc: 'role-based permission check' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-BROWSER',
    name: 'Browser',
    detectPatterns: [
      /\bbrowser\b/i,
      /\bpuppeteer\b/i,
      /\bplaywright\b/i,
      /\bselenium\b/i,
      /\bchromium\b/i,
    ],
    codeEvidencePatterns: [
      /(?:require|import)\s*.*puppeteer/i,
      /(?:require|import)\s*.*playwright/i,
      /(?:require|import)\s*.*selenium/i,
      /chromium\.launch/i,
      /browser\.newPage/i,
      /puppeteer\.launch/i,
      /playwright\.(?:chromium|firefox|webkit)/i,
      /webdriver/i,
    ],
    defensePatterns: [
      { pattern: /(?:不|do\s*not|never).*(?:導航|navigate).*(?:惡意|malicious)/i, desc: 'no malicious navigation' },
      { pattern: /(?:不|do\s*not|never).*(?:表單|form).*(?:輸入|input|enter).*(?:credentials?|密碼|password)/i, desc: 'no credential entry in forms' },
      { pattern: /(?:url|domain).*(?:allowlist|whitelist|blocklist)/i, desc: 'URL allowlist/blocklist' },
      { pattern: /(?:browser|瀏覽器).*(?:sandbox|沙箱|restriction|限制)/i, desc: 'browser sandbox restrictions' },
      { pattern: /(?:cookie|session|localStorage).*(?:protect|restrict|isolat|sanitiz|不|禁止)/i, desc: 'cookie/session protection' },
      { pattern: /(?:不|do\s*not|never).*(?:存取|access|read|use).*(?:cookie|session|localStorage)/i, desc: 'no cookie/session access' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-FILESYSTEM',
    name: 'File System',
    detectPatterns: [
      /\bfs\.write\b/i,
      /\bfs\.delete\b/i,
      /\brm\s+/,
      /\bexec\s*\(/,
      /\bshell\b/i,
      /\bbash\b/i,
    ],
    // File System is ubiquitous — almost all agents have it. Downgrade to medium.
    undefendedSeverity: 'medium',
    defensePatterns: [
      { pattern: /trash\s*>\s*rm|(?:用|use)\s*trash/i, desc: 'prefer trash over rm' },
      { pattern: /(?:不|do\s*not|never).*(?:執行|execute|run).*(?:來路不明|unknown|untrusted|unverified)/i, desc: 'no untrusted script execution' },
      { pattern: /(?:destructive|危險|破壞).*(?:command|指令|操作).*(?:confirm|確認)/i, desc: 'destructive command confirmation' },
      { pattern: /(?:confirm|確認).*(?:before|前|prior).*(?:delete|rm|remove|刪除)/i, desc: 'confirm before deletion' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-API',
    name: 'API/HTTP',
    detectPatterns: [
      /\bfetch\s*\(/,
      /\baxios\b/i,
      /\bcurl\b/i,
      /\brequest\s*\(/,
      /\bhttp\.post\b/i,
    ],
    defensePatterns: [
      { pattern: /(?:url|domain|endpoint).*(?:allowlist|whitelist|validate)/i, desc: 'URL/domain validation' },
      { pattern: /(?:rate[_-]?limit|throttl)/i, desc: 'rate limiting' },
      { pattern: /(?:api|http).*(?:auth|token|key)/i, desc: 'API authentication' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-DATABASE',
    name: 'Database',
    detectPatterns: [
      /\bdatabase\b/i,
      /\bmongodb\b/i,
      /\bpostgres\b/i,
      /\bmysql\b/i,
      /\bsupabase\b/i,
      /\bfirebase\b/i,
    ],
    codeEvidencePatterns: [
      /(?:require|import)\s*.*(?:mongoose|mongodb|pg|mysql|mysql2|sequelize|prisma|typeorm|knex|drizzle)/i,
      /(?:require|import)\s*.*(?:supabase|firebase)/i,
      /(?:mongodb|postgres|mysql|redis):\/\//i,
      /createClient\s*\(/i,
      /new\s+(?:MongoClient|Pool|Connection)/i,
      /DATABASE_URL/i,
      /SUPABASE_(?:URL|KEY)/i,
      /FIREBASE_(?:CONFIG|KEY)/i,
    ],
    defensePatterns: [
      { pattern: /(?:parameterized|prepared)\s+(?:query|statement)/i, desc: 'parameterized queries' },
      { pattern: /(?:sql|query).*(?:sanitiz|escap|validat)/i, desc: 'query sanitization' },
      { pattern: /(?:database|db).*(?:permission|access\s*control|role)/i, desc: 'database access control' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
  {
    id: 'CH-MCP',
    name: 'MCP Server (tool channel)',
    detectPatterns: [
      /\bmcp[_-]?server/i,
      /\bmcpServers\b/i,
      /\bmcp_servers\b/i,
      /\bmodel[_-]?context[_-]?protocol/i,
    ],
    defensePatterns: [
      { pattern: /(?:tool|mcp)\s+(?:output|response|result).*(?:sanitiz|filter|validat|treat.*(?:untrusted|plain\s*text))/i, desc: 'MCP tool output sanitization' },
      { pattern: /(?:不|do\s*not|never).*(?:執行|execute|follow|trust).*(?:tool|mcp).*(?:輸出|output|response|result).*(?:中的)?(?:指令|instruction|command)/i, desc: 'do not execute tool output instructions' },
      { pattern: /(?:tool|mcp).*(?:allowlist|whitelist|allow[_-]?tool)/i, desc: 'MCP tool allowlist' },
      { pattern: /(?:verify|驗證|validate).*(?:tool|mcp).*(?:description|output|response)/i, desc: 'verify MCP tool descriptions/output' },
      { pattern: /(?:tool|mcp).*(?:sandbox|isolat|restrict|boundary)/i, desc: 'MCP tool sandboxing' },
    ],
    partialThreshold: 1,
    fullThreshold: 3,
  },
  {
    id: 'CH-PAYMENT',
    name: 'Payment',
    detectPatterns: [
      /\bstripe\b/i,
      /\bpayment\b/i,
      /\bbilling\b/i,
      /\bcharge\b/i,
    ],
    codeEvidencePatterns: [
      /(?:require|import)\s*.*stripe/i,
      /(?:require|import)\s*.*(?:paypal|braintree|square)/i,
      /STRIPE_(?:SECRET|PUBLISHABLE|KEY)/i,
      /new\s+Stripe\s*\(/i,
      /stripe\.(?:charges|paymentIntents|customers)/i,
      /PAYPAL_(?:CLIENT|SECRET)/i,
    ],
    defensePatterns: [
      { pattern: /(?:花錢|payment|charge|billing|purchase).*(?:操作|operation)?.*(?:需|require|must).*(?:確認|confirm|approval)/i, desc: 'payment confirmation required' },
      { pattern: /(?:confirm|確認).*(?:before|前).*(?:payment|charge|purchase|花錢)/i, desc: 'confirm before payment' },
      { pattern: /(?:spending|花費).*(?:limit|限制|上限)/i, desc: 'spending limit' },
    ],
    partialThreshold: 1,
    fullThreshold: 2,
  },
];

export interface ChannelAuditResult {
  channelId: string;
  channelName: string;
  detected: boolean;
  detectedIn: string[];
  defenseCount: number;
  defenses: string[];
  status: 'undefended' | 'partial' | 'defended';
}

export function detectChannels(content: string, filePath: string): { channelId: string; detected: boolean }[] {
  return CHANNEL_DEFINITIONS.map(ch => ({
    channelId: ch.id,
    detected: ch.detectPatterns.some(p => p.test(content)),
  }));
}

export function checkChannelDefenses(content: string, channelId: string): { defenses: string[] } {
  const channel = CHANNEL_DEFINITIONS.find(ch => ch.id === channelId);
  if (!channel) return { defenses: [] };

  const defenses: string[] = [];
  for (const dp of channel.defensePatterns) {
    if (dp.pattern.test(content)) {
      defenses.push(dp.desc);
    }
  }
  return { defenses };
}

export function generateChannelFindings(auditResults: ChannelAuditResult[], targetPath: string): Finding[] {
  const findings: Finding[] = [];

  for (const result of auditResults) {
    if (!result.detected) continue;

    const channel = CHANNEL_DEFINITIONS.find(ch => ch.id === result.channelId)!;

    if (result.status === 'undefended') {
      findings.push({
        id: `${result.channelId}-UNDEFENDED`,
        scanner: 'channel-surface-auditor',
        severity: channel.undefendedSeverity || 'high',
        title: `Undefended channel: ${result.channelName}`,
        description: `Agent has access to ${result.channelName} but no channel-specific defenses were found. An attacker could exploit this channel to inject instructions or exfiltrate data.`,
        file: targetPath,
        recommendation: `Add channel-specific defenses for ${result.channelName}. ${getChannelRecommendation(result.channelId)}`,
        confidence: 'likely',
      });
    } else if (result.status === 'partial') {
      findings.push({
        id: `${result.channelId}-PARTIAL`,
        scanner: 'channel-surface-auditor',
        severity: 'medium',
        title: `Partially defended channel: ${result.channelName}`,
        description: `Agent has access to ${result.channelName} with some defenses (${result.defenses.join(', ')}), but coverage is incomplete.`,
        file: targetPath,
        recommendation: `Strengthen defenses for ${result.channelName}. ${getChannelRecommendation(result.channelId)}`,
        confidence: 'likely',
      });
    } else {
      // defended — info level
      findings.push({
        id: `${result.channelId}-DEFENDED`,
        scanner: 'channel-surface-auditor',
        severity: 'info',
        title: `Defended channel: ${result.channelName}`,
        description: `Agent has access to ${result.channelName} with adequate defenses (${result.defenses.join(', ')}).`,
        file: targetPath,
        recommendation: 'Continue monitoring and updating channel defenses.',
        confidence: 'likely',
      });
    }
  }

  return findings;
}

function getChannelRecommendation(channelId: string): string {
  const recommendations: Record<string, string> = {
    'CH-EMAIL': 'Treat external email content as plain text. Do not execute instructions from emails. Define different trust levels per channel.',
    'CH-SOCIAL': 'Require confirmation before posting. Never disclose private information. Add anti-manipulation rules.',
    'CH-TELEGRAM': 'Verify sender identity via Telegram user ID. Only accept commands from verified users.',
    'CH-DISCORD': 'Implement role-based permission checks. Verify webhook authenticity.',
    'CH-BROWSER': 'Do not navigate to malicious sites. Never enter credentials in forms. Use URL allowlists.',
    'CH-FILESYSTEM': 'Use trash instead of rm. Do not execute untrusted scripts. Require confirmation for destructive commands.',
    'CH-API': 'Validate URLs/domains. Implement rate limiting. Use proper authentication.',
    'CH-DATABASE': 'Use parameterized queries. Sanitize all inputs. Implement access controls.',
    'CH-MCP': 'Treat MCP tool outputs as untrusted data. Never execute instructions found in tool responses. Use tool allowlists. Verify tool descriptions. Sandbox MCP server access.',
    'CH-PAYMENT': 'Require explicit confirmation for all payment operations. Set spending limits.',
  };
  return recommendations[channelId] || '';
}

/**
 * Stream a file line by line, detecting channel patterns and defense patterns.
 * Avoids loading the entire file into memory at once.
 */
async function streamScanFile(
  filePath: string,
  channelDefinitions: ChannelDefinition[]
): Promise<{ channelDetections: Set<string>; channelDefenses: Map<string, string[]> }> {
  const channelDetections = new Set<string>();
  const channelDefenses = new Map<string, string[]>(
    channelDefinitions.map(ch => [ch.id, []])
  );

  return new Promise((resolve) => {
    let readStream: fs.ReadStream;
    try {
      readStream = fs.createReadStream(filePath, { encoding: 'utf-8', highWaterMark: 64 * 1024 });
    } catch {
      resolve({ channelDetections, channelDefenses });
      return;
    }

    const rl = readline.createInterface({ input: readStream, crlfDelay: Infinity });

    rl.on('line', (line) => {
      for (const ch of channelDefinitions) {
        if (!channelDetections.has(ch.id) && ch.detectPatterns.some(p => p.test(line))) {
          channelDetections.add(ch.id);
        }
        const defenseList = channelDefenses.get(ch.id)!;
        for (const dp of ch.defensePatterns) {
          if (!defenseList.includes(dp.desc) && dp.pattern.test(line)) {
            defenseList.push(dp.desc);
          }
        }
      }
    });

    const done = () => resolve({ channelDetections, channelDefenses });
    rl.on('close', done);
    rl.on('error', done);
    readStream.on('error', () => { rl.close(); });
  });
}

/**
 * Stream a file line by line, searching for code-level evidence of channel integrations.
 * Exits early once all remaining channels have been confirmed.
 */
async function streamScanForCodeEvidence(
  filePath: string,
  channelsNeedingEvidence: ChannelDefinition[],
  alreadyFound: Set<string>
): Promise<Set<string>> {
  const found = new Set<string>();
  const remaining = channelsNeedingEvidence.filter(ch => !alreadyFound.has(ch.id));
  if (remaining.length === 0) return found;

  return new Promise((resolve) => {
    let readStream: fs.ReadStream;
    try {
      readStream = fs.createReadStream(filePath, { encoding: 'utf-8', highWaterMark: 64 * 1024 });
    } catch {
      resolve(found);
      return;
    }

    const rl = readline.createInterface({ input: readStream, crlfDelay: Infinity });

    rl.on('line', (line) => {
      for (const ch of remaining) {
        if (!found.has(ch.id) && ch.codeEvidencePatterns!.some(p => p.test(line))) {
          found.add(ch.id);
        }
      }
      // Early exit: all remaining channels found in this file
      if (remaining.every(ch => found.has(ch.id))) {
        rl.close();
        readStream.destroy();
      }
    });

    const done = () => resolve(found);
    rl.on('close', done);
    rl.on('error', done);
    readStream.on('error', () => { rl.close(); });
  });
}

export const channelSurfaceAuditor: ScannerModule = {
  name: 'Channel Surface Auditor',
  description: 'Detects which external channels the agent controls and checks whether each channel has adequate defenses',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Scan both prompt files and config files
    const promptFiles = await findPromptFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);
    const configFiles = await findConfigFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);
    const allFiles = [...new Set([...promptFiles, ...configFiles])];

    // Also scan source files for code-level evidence of channel integrations
    const sourceFiles = await findFiles(targetPath, [
      '**/*.ts', '**/*.js', '**/*.py', '**/*.sh',
    ], options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    // Build a set of channels that have code-level evidence.
    // Channels without codeEvidencePatterns are always confirmed.
    const channelsWithCodeEvidence = new Set<string>();
    for (const ch of CHANNEL_DEFINITIONS) {
      if (!ch.codeEvidencePatterns) {
        channelsWithCodeEvidence.add(ch.id);
      }
    }

    // For channels that require code evidence, stream files with early exit
    const channelsNeedingEvidence = CHANNEL_DEFINITIONS.filter(
      ch => ch.codeEvidencePatterns && !channelsWithCodeEvidence.has(ch.id)
    );
    if (channelsNeedingEvidence.length > 0) {
      const filesToCheck = [...sourceFiles, ...allFiles];
      for (const file of filesToCheck) {
        if (channelsNeedingEvidence.every(ch => channelsWithCodeEvidence.has(ch.id))) break;
        const found = await streamScanForCodeEvidence(file, channelsNeedingEvidence, channelsWithCodeEvidence);
        for (const id of found) {
          channelsWithCodeEvidence.add(id);
        }
      }
    }

    // Track per-channel results
    const channelResults = new Map<string, ChannelAuditResult>();
    for (const ch of CHANNEL_DEFINITIONS) {
      channelResults.set(ch.id, {
        channelId: ch.id,
        channelName: ch.name,
        detected: false,
        detectedIn: [],
        defenseCount: 0,
        defenses: [],
        status: 'undefended',
      });
    }

    // Pass 1: Stream each file for channel detection and defense patterns
    for (const file of allFiles) {
      const { channelDetections, channelDefenses } = await streamScanFile(file, CHANNEL_DEFINITIONS);

      for (const id of channelDetections) {
        const result = channelResults.get(id)!;
        result.detected = true;
        result.detectedIn.push(file);
      }

      for (const [id, defenses] of channelDefenses) {
        if (defenses.length > 0) {
          const result = channelResults.get(id)!;
          result.defenses.push(...defenses);
        }
      }
    }

    // Deduplicate and determine status
    for (const [, result] of channelResults) {
      result.defenses = [...new Set(result.defenses)];
      result.defenseCount = result.defenses.length;

      if (!result.detected) continue;

      const channel = CHANNEL_DEFINITIONS.find(ch => ch.id === result.channelId)!;
      if (result.defenseCount >= channel.fullThreshold) {
        result.status = 'defended';
      } else if (result.defenseCount >= channel.partialThreshold) {
        result.status = 'partial';
      } else {
        result.status = 'undefended';
      }
    }

    // Generate findings
    const auditResults = Array.from(channelResults.values());
    const channelFindings = generateChannelFindings(auditResults, targetPath);

    // Downgrade channels without code evidence to info
    for (const f of channelFindings) {
      const channelId = f.id!.split('-').slice(0, 2).join('-');
      if (!channelsWithCodeEvidence.has(channelId) && f.severity !== 'info') {
        f.severity = 'info';
        f.description += ' [no code-level integration evidence found — mention only]';
      }
    }

    // Downgrade test/doc findings
    for (const f of channelFindings) {
      if (f.file && path.extname(f.file) !== '' && isTestOrDocFile(f.file)) {
        if (f.severity === 'critical') f.severity = 'medium';
        else if (f.severity === 'high') f.severity = 'info';
        f.description += ' [test/doc file — severity reduced]';
      }
    }

    findings.push(...channelFindings);

    return {
      scanner: 'Channel Surface Auditor',
      findings,
      scannedFiles: allFiles.length,
      duration: Date.now() - start,
    };
  },
};
