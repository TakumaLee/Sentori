/**
 * MCP Server Auditor Prototype (P1)
 * 
 * Purpose: Validate technical feasibility of MCP server configuration scanning.
 * Focus areas:
 *   1. Overly permissive permissions (wildcard "*")
 *   2. Sensitive API endpoint exposure (/admin, /config, etc.)
 *   3. Unsafe shell execution in tool definitions
 * 
 * Output: JSON risk report
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';

// ============================================================
// Types
// ============================================================

interface McpServerConfig {
  mcpServers?: Record<string, McpServerEntry>;
  servers?: Record<string, McpServerEntry>;
  mcp_servers?: Record<string, McpServerEntry>;
  [key: string]: unknown;
}

interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  endpoint?: string;
  tools?: McpToolDefinition[];
  permissions?: string[] | Record<string, unknown>;
  allowlist?: string[];
  denylist?: string[];
  [key: string]: unknown;
}

interface McpToolDefinition {
  name: string;
  description?: string;
  command?: string;
  execute?: string;
  shell?: boolean;
  permissions?: string[];
  [key: string]: unknown;
}

// Zod schemas for MCP config validation — prevents downstream crashes from
// malformed config files in scanned projects.
const McpToolDefinitionSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  command: z.string().optional(),
  execute: z.string().optional(),
  shell: z.boolean().optional(),
  permissions: z.array(z.string()).optional(),
}).passthrough();

const McpServerEntrySchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string(), z.string()).optional(),
  url: z.string().optional(),
  endpoint: z.string().optional(),
  tools: z.array(McpToolDefinitionSchema).optional(),
  permissions: z.union([z.array(z.string()), z.record(z.string(), z.unknown())]).optional(),
  allowlist: z.array(z.string()).optional(),
  denylist: z.array(z.string()).optional(),
}).passthrough();

const McpServerConfigSchema = z.object({
  mcpServers: z.record(z.string(), McpServerEntrySchema).optional(),
  servers: z.record(z.string(), McpServerEntrySchema).optional(),
  mcp_servers: z.record(z.string(), McpServerEntrySchema).optional(),
}).passthrough();

interface RiskReport {
  serverName: string;
  risks: Risk[];
  severity: 'critical' | 'high' | 'medium' | 'info';
  score: number; // 0-100, lower is more risky
}

interface Risk {
  type: 'permission' | 'endpoint' | 'shell_execution' | 'general';
  severity: 'critical' | 'high' | 'medium' | 'info';
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
}

// ============================================================
// Risk Detection Rules
// ============================================================

const SENSITIVE_ENDPOINTS = [
  '/admin',
  '/config',
  '/settings',
  '/api/admin',
  '/api/config',
  '/debug',
  '/internal',
  '/_internal',
  '/system',
  '/management',
  '/console',
];

const DANGEROUS_SHELL_PATTERNS = [
  /exec\s*\(/i,
  /system\s*\(/i,
  /spawn\s*\(/i,
  /execFile\s*\(/i,
  /child_process/i,
  /subprocess/i,
  /os\.system/i,
  /shell\s*=\s*true/i,
  /\/bin\/(ba)?sh/,
  /cmd\.exe/i,
  /powershell/i,
];

// ============================================================
// Main Scanner
// ============================================================

export const mcpServerAuditorPrototype: ScannerModule = {
  name: 'MCP Server Auditor (Prototype)',
  description: 'Prototype scanner for MCP server security auditing: permissions, endpoints, shell execution',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    
    try {
      const configFiles = await findMcpConfigFiles(targetPath);
      
      for (const configFile of configFiles) {
        const config = await loadConfig(configFile);
        if (!config) continue;

        const riskReports = auditMcpConfig(config, configFile);
        
        // Convert risk reports to findings
        for (const report of riskReports) {
          for (const risk of report.risks) {
            findings.push({
              scanner: 'MCP Server Auditor (Prototype)',
              severity: risk.severity,
              title: risk.title,
              description: risk.description,
              evidence: risk.evidence,
              file: configFile,
              recommendation: risk.recommendation,
              confidence: 'definite',
            });
          }
        }
      }

      return {
        scanner: 'MCP Server Auditor (Prototype)',
        findings,
        scannedFiles: configFiles.length,
        duration: Date.now() - start,
      };
    } catch (error) {
      const err = error as Error;
      return {
        scanner: 'MCP Server Auditor (Prototype)',
        findings: [{
          scanner: 'MCP Server Auditor (Prototype)',
          severity: 'info',
          title: 'Scanner Error',
          description: `Failed to scan: ${err.message}`,
          confidence: 'definite',
        }],
        scannedFiles: 0,
        duration: Date.now() - start,
      };
    }
  },
};

// ============================================================
// Config File Discovery
// ============================================================

async function findMcpConfigFiles(rootPath: string): Promise<string[]> {
  const configFiles: string[] = [];
  
  const CANDIDATE_NAMES = [
    'mcp.json',
    'mcp.yaml',
    'mcp.yml',
    'mcp-config.json',
    'mcp-config.yaml',
    'mcp-config.yml',
    'mcp_servers.json',
    'config.json', // Generic, but common
  ];

  async function walk(dir: string) {
    try {
      const entries = await fs.promises.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        // Skip common irrelevant directories
        if (entry.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build', '.next', 'coverage'].includes(entry.name)) {
            continue;
          }
          await walk(fullPath);
        } else if (entry.isFile()) {
          if (CANDIDATE_NAMES.includes(entry.name.toLowerCase())) {
            configFiles.push(fullPath);
          }
        }
      }
    } catch (err) {
      // Skip unreadable directories
    }
  }

  await walk(rootPath);
  return configFiles;
}

// ============================================================
// Config Loading
// ============================================================

async function loadConfig(filePath: string): Promise<McpServerConfig | null> {
  let raw: unknown;
  try {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    if (filePath.endsWith('.json')) {
      raw = JSON.parse(content);
    } else if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      raw = yaml.load(content);
    } else {
      return null;
    }
  } catch (err) {
    process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'McpServerAuditor', file: filePath, error: 'config read/parse failed', message: String(err) }) + '\n');
    return null;
  }
  const result = McpServerConfigSchema.safeParse(raw);
  if (!result.success) {
    process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'McpServerAuditor', file: filePath, error: 'MCP config schema validation failed — using raw', issues: result.error.issues }) + '\n');
    return raw as McpServerConfig;
  }
  return result.data as McpServerConfig;
}

// ============================================================
// Risk Auditing Logic
// ============================================================

export function auditMcpConfig(config: McpServerConfig, filePath: string): RiskReport[] {
  const reports: RiskReport[] = [];
  
  // Find server configurations
  const servers = config.mcpServers || config.servers || config.mcp_servers;
  
  if (!servers || typeof servers !== 'object') {
    return reports;
  }

  for (const [serverName, serverConfig] of Object.entries(servers)) {
    const risks = auditSingleServer(serverName, serverConfig);
    
    if (risks.length > 0) {
      const severity = calculateOverallSeverity(risks);
      const score = calculateRiskScore(risks);
      
      reports.push({
        serverName,
        risks,
        severity,
        score,
      });
    }
  }

  return reports;
}

function auditSingleServer(name: string, config: McpServerEntry): Risk[] {
  const risks: Risk[] = [];

  // Check 1: Wildcard permissions
  risks.push(...checkWildcardPermissions(name, config));

  // Check 2: Sensitive endpoint exposure
  risks.push(...checkSensitiveEndpoints(name, config));

  // Check 3: Unsafe shell execution
  risks.push(...checkUnsafeShellExecution(name, config));

  return risks;
}

// ============================================================
// Check 1: Wildcard Permissions
// ============================================================

function checkWildcardPermissions(serverName: string, config: McpServerEntry): Risk[] {
  const risks: Risk[] = [];

  // Check permissions field
  if (config.permissions) {
    if (Array.isArray(config.permissions)) {
      if (config.permissions.includes('*')) {
        risks.push({
          type: 'permission',
          severity: 'critical',
          title: 'Wildcard Permission Detected',
          description: `Server "${serverName}" grants wildcard permission "*", allowing unrestricted access.`,
          evidence: `permissions: ${JSON.stringify(config.permissions)}`,
          recommendation: 'Use principle of least privilege. Specify exact permissions needed (e.g., ["read:files", "write:logs"]).',
        });
      }
      
      // Check for overly broad patterns
      const broadPermissions = config.permissions.filter(p => 
        typeof p === 'string' && (p.endsWith(':*') || p === 'admin' || p === 'root')
      );
      
      if (broadPermissions.length > 0) {
        risks.push({
          type: 'permission',
          severity: 'high',
          title: 'Overly Broad Permissions',
          description: `Server "${serverName}" has broad permissions: ${broadPermissions.join(', ')}`,
          evidence: `permissions: ${JSON.stringify(broadPermissions)}`,
          recommendation: 'Narrow down permissions to specific actions (e.g., "read:user_data" instead of "read:*").',
        });
      }
    } else if (typeof config.permissions === 'object') {
      // Check for wildcard in object-style permissions
      const permObj = config.permissions as Record<string, unknown>;
      if (permObj['*'] !== undefined) {
        risks.push({
          type: 'permission',
          severity: 'critical',
          title: 'Wildcard Permission Key',
          description: `Server "${serverName}" has wildcard permission key "*".`,
          evidence: `permissions: ${JSON.stringify(permObj)}`,
          recommendation: 'Remove wildcard permission. Define explicit permission keys.',
        });
      }
    }
  }

  // Check allowlist (empty allowlist = allow all)
  if (config.allowlist && Array.isArray(config.allowlist) && config.allowlist.length === 0) {
    risks.push({
      type: 'permission',
      severity: 'medium',
      title: 'Empty Allowlist',
      description: `Server "${serverName}" has an empty allowlist, potentially allowing all access.`,
      evidence: 'allowlist: []',
      recommendation: 'Define explicit allowlist entries or remove the field if not used.',
    });
  }

  return risks;
}

// ============================================================
// Check 2: Sensitive Endpoint Exposure
// ============================================================

function checkSensitiveEndpoints(serverName: string, config: McpServerEntry): Risk[] {
  const risks: Risk[] = [];

  const endpoints = [config.url, config.endpoint].filter(Boolean) as string[];
  
  for (const endpoint of endpoints) {
    for (const sensitive of SENSITIVE_ENDPOINTS) {
      if (endpoint.includes(sensitive)) {
        risks.push({
          type: 'endpoint',
          severity: 'high',
          title: 'Sensitive Endpoint Exposed',
          description: `Server "${serverName}" exposes sensitive endpoint: ${endpoint}`,
          evidence: `endpoint: "${endpoint}" contains "${sensitive}"`,
          recommendation: `Avoid exposing ${sensitive} endpoints in MCP server configs. Use internal-only endpoints or add authentication.`,
        });
      }
    }

    // Check for HTTP (non-HTTPS)
    if (endpoint.startsWith('http://') && !endpoint.includes('localhost') && !endpoint.includes('127.0.0.1')) {
      risks.push({
        type: 'endpoint',
        severity: 'medium',
        title: 'Unencrypted Endpoint',
        description: `Server "${serverName}" uses unencrypted HTTP endpoint.`,
        evidence: `endpoint: "${endpoint}"`,
        recommendation: 'Use HTTPS to encrypt data in transit.',
      });
    }
  }

  return risks;
}

// ============================================================
// Check 3: Unsafe Shell Execution
// ============================================================

function checkUnsafeShellExecution(serverName: string, config: McpServerEntry): Risk[] {
  const risks: Risk[] = [];

  // Check tools array
  if (config.tools && Array.isArray(config.tools)) {
    for (const tool of config.tools) {
      if (typeof tool !== 'object') continue;

      // Check for shell execution flags
      if (tool.shell === true) {
        risks.push({
          type: 'shell_execution',
          severity: 'critical',
          title: 'Unsafe Shell Execution Enabled',
          description: `Tool "${tool.name}" in server "${serverName}" has shell execution enabled.`,
          evidence: `tool: ${tool.name}, shell: true`,
          recommendation: 'Disable shell execution or use parameterized commands with strict validation.',
        });
      }

      // Check command/execute fields for dangerous patterns
      const commandFields = [tool.command, tool.execute].filter(Boolean) as string[];
      
      for (const cmd of commandFields) {
        for (const pattern of DANGEROUS_SHELL_PATTERNS) {
          if (pattern.test(cmd)) {
            risks.push({
              type: 'shell_execution',
              severity: 'high',
              title: 'Dangerous Shell Pattern Detected',
              description: `Tool "${tool.name}" in server "${serverName}" contains potentially dangerous shell execution pattern.`,
              evidence: `command: "${cmd.substring(0, 100)}${cmd.length > 100 ? '...' : ''}"`,
              recommendation: 'Use safe subprocess execution with argument arrays instead of shell strings. Validate all inputs.',
            });
            break; // Only report once per command
          }
        }
      }
    }
  }

  // Check command at server level
  if (config.command) {
    for (const pattern of DANGEROUS_SHELL_PATTERNS) {
      if (pattern.test(config.command)) {
        risks.push({
          type: 'shell_execution',
          severity: 'medium',
          title: 'Server Command Uses Shell',
          description: `Server "${serverName}" command may use shell execution.`,
          evidence: `command: "${config.command.substring(0, 100)}${config.command.length > 100 ? '...' : ''}"`,
          recommendation: 'Review command for shell injection risks. Use argument arrays when possible.',
        });
        break;
      }
    }
  }

  return risks;
}

// ============================================================
// Scoring & Severity
// ============================================================

function calculateOverallSeverity(risks: Risk[]): 'critical' | 'high' | 'medium' | 'info' {
  if (risks.some(r => r.severity === 'critical')) return 'critical';
  if (risks.some(r => r.severity === 'high')) return 'high';
  if (risks.some(r => r.severity === 'medium')) return 'medium';
  return 'info';
}

function calculateRiskScore(risks: Risk[]): number {
  const severityWeights = {
    critical: 40,
    high: 20,
    medium: 10,
    info: 1,
  };

  const totalDeduction = risks.reduce((sum, risk) => {
    return sum + severityWeights[risk.severity];
  }, 0);

  return Math.max(0, 100 - totalDeduction);
}

// ============================================================
// Export for Testing
// ============================================================

export type {
  McpServerConfig,
  RiskReport,
  Risk,
};

export {
  findMcpConfigFiles,
  loadConfig,
};
