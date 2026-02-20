/**
 * Tests for MCP Server Auditor Prototype
 */

import * as path from 'path';
import * as fs from 'fs';
import { mcpServerAuditorPrototype, auditMcpConfig, McpServerConfig } from '../src/scanners/mcp-server-auditor-prototype';

describe('MCP Server Auditor Prototype', () => {
  const testDataPath = path.join(__dirname, '../test-data/mcp-test-configs');

  describe('Scanner Integration', () => {
    it('should return valid scan result structure', async () => {
      const result = await mcpServerAuditorPrototype.scan(testDataPath);
      
      expect(result.scanner).toBe('MCP Server Auditor (Prototype)');
      expect(result).toHaveProperty('scannedFiles');
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should detect vulnerabilities from config object', () => {
      const vulnConfigPath = path.join(testDataPath, 'vulnerable-mcp-config.json');
      const vulnConfig = JSON.parse(fs.readFileSync(vulnConfigPath, 'utf-8'));
      const reports = auditMcpConfig(vulnConfig, 'test.json');
      
      expect(reports.length).toBeGreaterThan(0);
      
      const criticalServers = reports.filter(r => r.severity === 'critical');
      const highSeverityRisks = reports.flatMap(r => r.risks).filter(r => r.severity === 'high');
      
      expect(criticalServers.length).toBeGreaterThan(0);
      expect(highSeverityRisks.length).toBeGreaterThan(0);
    });

    it('should have minimal findings for safe config', () => {
      const safeConfigPath = path.join(testDataPath, 'safe-mcp-config.json');
      const safeConfig = JSON.parse(fs.readFileSync(safeConfigPath, 'utf-8'));
      const reports = auditMcpConfig(safeConfig, 'test.json');
      
      // Safe config should produce no risk reports
      expect(reports.length).toBe(0);
    });
  });

  describe('Wildcard Permission Detection', () => {
    it('should detect wildcard array permission', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            permissions: ['*']
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const wildcardRisks = reports[0]?.risks.filter(r => r.title.includes('Wildcard'));
      
      expect(wildcardRisks?.length).toBeGreaterThan(0);
      expect(wildcardRisks?.[0].severity).toBe('critical');
    });

    it('should detect wildcard object permission', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            permissions: {
              '*': true
            }
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const wildcardRisks = reports[0]?.risks.filter(r => r.title.includes('Wildcard'));
      
      expect(wildcardRisks?.length).toBeGreaterThan(0);
      expect(wildcardRisks?.[0].severity).toBe('critical');
    });

    it('should detect overly broad permissions', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            permissions: ['read:*', 'admin']
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const broadRisks = reports[0]?.risks.filter(r => r.title.includes('Broad'));
      
      expect(broadRisks?.length).toBeGreaterThan(0);
      expect(broadRisks?.[0].severity).toBe('high');
    });

    it('should flag empty allowlist', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            allowlist: []
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const allowlistRisks = reports[0]?.risks.filter(r => r.title.includes('Allowlist'));
      
      expect(allowlistRisks?.length).toBeGreaterThan(0);
    });
  });

  describe('Sensitive Endpoint Detection', () => {
    it('should detect /admin endpoint', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            url: 'https://api.example.com/admin'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const endpointRisks = reports[0]?.risks.filter(r => r.type === 'endpoint');
      
      expect(endpointRisks?.length).toBeGreaterThan(0);
      expect(endpointRisks?.[0].severity).toBe('high');
      expect(endpointRisks?.[0].description).toContain('/admin');
    });

    it('should detect /config endpoint', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            endpoint: 'https://api.example.com/config'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const endpointRisks = reports[0]?.risks.filter(r => r.type === 'endpoint');
      
      expect(endpointRisks?.length).toBeGreaterThan(0);
    });

    it('should flag unencrypted HTTP endpoints', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            url: 'http://api.example.com/data'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const httpRisks = reports[0]?.risks.filter(r => r.title.includes('Unencrypted'));
      
      expect(httpRisks?.length).toBeGreaterThan(0);
      expect(httpRisks?.[0].severity).toBe('medium');
    });

    it('should allow HTTP for localhost', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            url: 'http://localhost:3000/api'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      
      // Should not generate any reports for localhost HTTP
      const httpRisks = reports.flatMap(r => r.risks).filter(r => r.title.includes('Unencrypted'));
      expect(httpRisks.length).toBe(0);
    });
  });

  describe('Unsafe Shell Execution Detection', () => {
    it('should detect shell=true flag', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            tools: [
              {
                name: 'exec',
                shell: true
              }
            ]
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const shellRisks = reports[0]?.risks.filter(r => r.type === 'shell_execution');
      
      expect(shellRisks?.length).toBeGreaterThan(0);
      expect(shellRisks?.[0].severity).toBe('critical');
    });

    it('should detect dangerous shell patterns in tool commands', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            tools: [
              {
                name: 'exec',
                command: 'child_process.exec(userInput)'
              }
            ]
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const shellRisks = reports[0]?.risks.filter(r => r.type === 'shell_execution');
      
      expect(shellRisks?.length).toBeGreaterThan(0);
      expect(shellRisks?.[0].severity).toBe('high');
    });

    it('should detect shell patterns in server command', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            command: '/bin/bash -c "node server.js"'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      const shellRisks = reports[0]?.risks.filter(r => r.type === 'shell_execution');
      
      expect(shellRisks?.length).toBeGreaterThan(0);
    });

    it('should detect multiple dangerous patterns', () => {
      const patterns = [
        'exec(',
        'system(',
        'spawn(',
        'os.system',
        'subprocess',
        'powershell',
      ];

      for (const pattern of patterns) {
        const config: McpServerConfig = {
          mcpServers: {
            'test-server': {
              tools: [
                {
                  name: 'test',
                  command: `some code with ${pattern}`
                }
              ]
            }
          }
        };

        const reports = auditMcpConfig(config, 'test.json');
        expect(reports[0]?.risks.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Risk Scoring', () => {
    it('should assign critical severity for critical risks', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            permissions: ['*'],
            tools: [
              {
                name: 'exec',
                shell: true
              }
            ]
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      expect(reports[0].severity).toBe('critical');
      expect(reports[0].score).toBeLessThan(50);
    });

    it('should give high score for safe config', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'test-server': {
            permissions: ['read:docs'],
            url: 'https://api.example.com/safe'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      expect(reports.length).toBe(0); // No risks = no report
    });
  });

  describe('Multiple Server Analysis', () => {
    it('should analyze multiple servers independently', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'safe-server': {
            permissions: ['read:docs']
          },
          'unsafe-server': {
            permissions: ['*']
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      expect(reports.length).toBe(1); // Only unsafe server should report
      expect(reports[0].serverName).toBe('unsafe-server');
    });

    it('should handle mixed severity across servers', () => {
      const config: McpServerConfig = {
        mcpServers: {
          'server-1': {
            permissions: ['admin']
          },
          'server-2': {
            permissions: ['*']
          },
          'server-3': {
            url: 'http://example.com/api'
          }
        }
      };

      const reports = auditMcpConfig(config, 'test.json');
      expect(reports.length).toBeGreaterThan(0);
      
      const criticalReports = reports.filter(r => r.severity === 'critical');
      expect(criticalReports.length).toBeGreaterThan(0);
    });
  });
});
