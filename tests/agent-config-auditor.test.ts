import { auditAgentConfig } from '../src/scanners/agent-config-auditor';
import { agentConfigAuditor } from '../src/scanners/agent-config-auditor';
import * as fs from 'fs';
import * as path from 'path';

describe('Agent Config Auditor', () => {
  describe('auditAgentConfig', () => {
    // AC-001: Gateway exposed to network
    it('should detect bind 0.0.0.0 as critical', () => {
      const config = { gateway: { bind: '0.0.0.0', port: 8080 } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Gateway exposed to network');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
    });

    it('should detect non-loopback bind address', () => {
      const config = { gateway: { bind: '192.168.1.100', port: 8080 } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Gateway exposed to network');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
    });

    it('should not flag bind 127.0.0.1', () => {
      const config = { gateway: { bind: '127.0.0.1', port: 8080, token: 'abc' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Gateway exposed to network');
      expect(f).toBeUndefined();
    });

    it('should not flag bind localhost', () => {
      const config = { gateway: { bind: 'localhost', port: 8080, token: 'abc' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Gateway exposed to network');
      expect(f).toBeUndefined();
    });

    // AC-002: No gateway authentication
    it('should detect missing auth on gateway', () => {
      const config = { gateway: { bind: '127.0.0.1', port: 8080 } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No gateway authentication');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
    });

    it('should not flag when token is present', () => {
      const config = { gateway: { bind: '127.0.0.1', port: 8080, token: 'my-secret-token' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No gateway authentication');
      expect(f).toBeUndefined();
    });

    it('should not flag when auth object is present', () => {
      const config = { gateway: { port: 8080 }, auth: { type: 'bearer', token: 'xxx' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No gateway authentication');
      expect(f).toBeUndefined();
    });

    // AC-003: No sender restriction
    it('should detect missing allowFrom on channel', () => {
      const config = {
        gateway: { port: 8080, token: 'abc' },
        channels: [{ name: 'telegram', type: 'telegram' }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No sender restriction on messaging channel');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
    });

    it('should not flag when allowFrom is present', () => {
      const config = {
        gateway: { port: 8080, token: 'abc' },
        channels: [{ name: 'telegram', type: 'telegram', allowFrom: ['123456'] }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No sender restriction on messaging channel');
      expect(f).toBeUndefined();
    });

    it('should not flag when allowedUsers is present', () => {
      const config = {
        channels: [{ name: 'discord', allowedUsers: ['user1'] }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No sender restriction on messaging channel');
      expect(f).toBeUndefined();
    });

    // AC-004: DM policy open
    it('should detect dmPolicy open on channel', () => {
      const config = {
        channels: [{ name: 'telegram', dmPolicy: 'open', allowFrom: ['123'] }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'DM policy allows anyone to message');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
    });

    it('should detect top-level dmPolicy open', () => {
      const config = { dmPolicy: 'open' };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'DM policy allows anyone to message');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
    });

    it('should not flag dmPolicy restricted', () => {
      const config = {
        channels: [{ name: 'telegram', dmPolicy: 'restricted', allowFrom: ['123'] }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'DM policy allows anyone to message');
      expect(f).toBeUndefined();
    });

    // AC-005: Bot token in plaintext
    it('should detect Telegram bot token in config', () => {
      const config = {
        botToken: '1234567890:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQs',
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Bot token in plaintext config');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
    });

    it('should detect Anthropic API key in config', () => {
      const config = {
        apiKey: 'sk-ant-api03-AABBCCDDEE1234567890abcdefghij',
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Bot token in plaintext config');
      expect(f).toBeDefined();
    });

    it('should detect OpenAI project key in config', () => {
      const config = {
        apiKey: 'sk-proj-AABBCCDDEE1234567890abcdefghij',
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Bot token in plaintext config');
      expect(f).toBeDefined();
    });

    // AC-006: Default port
    it('should detect default port 18789', () => {
      const config = { gateway: { port: 18789, token: 'abc' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Using default port');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
    });

    it('should not flag non-default port', () => {
      const config = { gateway: { port: 9999, token: 'abc' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Using default port');
      expect(f).toBeUndefined();
    });

    // AC-007: No logging
    it('should detect missing logging config', () => {
      const config = { gateway: { port: 8080, token: 'abc' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No logging configured');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
    });

    it('should not flag when logging is present', () => {
      const config = { gateway: { port: 8080, token: 'abc' }, logging: { level: 'info' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'No logging configured');
      expect(f).toBeUndefined();
    });

    // AC-008: No redactSensitive
    it('should detect missing redactSensitive', () => {
      const config = { gateway: { port: 8080, token: 'abc' } };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Sensitive data not redacted in logs');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
    });

    it('should not flag when redactSensitive is set', () => {
      const config = { gateway: { port: 8080, token: 'abc' }, redactSensitive: true };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Sensitive data not redacted in logs');
      expect(f).toBeUndefined();
    });

    // AC-009: Group policy not restricted
    it('should detect groupPolicy open on channel', () => {
      const config = {
        channels: [{ name: 'telegram', groupPolicy: 'open', allowFrom: ['123'] }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Group policy not restricted');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
    });

    it('should detect top-level groupPolicy open', () => {
      const config = { groupPolicy: 'open' };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Group policy not restricted');
      expect(f).toBeDefined();
    });

    it('should not flag groupPolicy allowlist', () => {
      const config = {
        channels: [{ name: 'telegram', groupPolicy: 'allowlist', allowFrom: ['123'] }],
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      const f = findings.find(f => f.title === 'Group policy not restricted');
      expect(f).toBeUndefined();
    });

    // Combined insecure config
    it('should find multiple issues in a fully insecure config', () => {
      const config = {
        gateway: { bind: '0.0.0.0', port: 18789 },
        channels: [{ name: 'telegram', dmPolicy: 'open', groupPolicy: 'open' }],
        botToken: '1234567890:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQs',
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      expect(findings.length).toBeGreaterThanOrEqual(5);
      const criticals = findings.filter(f => f.severity === 'critical');
      expect(criticals.length).toBeGreaterThanOrEqual(2);
    });

    // Secure config
    it('should find minimal issues in a secure config', () => {
      const config = {
        gateway: { bind: '127.0.0.1', port: 9999, token: 'secure-token-here' },
        channels: [{ name: 'telegram', allowFrom: ['123456'], dmPolicy: 'restricted', groupPolicy: 'allowlist' }],
        logging: { level: 'info' },
        redactSensitive: true,
      };
      const findings = auditAgentConfig(config, 'tetora.json');
      // Should have zero or very few findings
      const nonInfo = findings.filter(f => f.severity !== 'info');
      expect(nonInfo.length).toBe(0);
    });
  });

  describe('scan integration', () => {
    const tmpDir = path.join(__dirname, '__tmp_agent_config_test__');

    beforeEach(() => {
      fs.mkdirSync(tmpDir, { recursive: true });
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should scan tetora.json files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'tetora.json'),
        JSON.stringify({
          gateway: { bind: '0.0.0.0', port: 18789 },
          channels: [{ name: 'telegram' }],
        })
      );

      const result = await agentConfigAuditor.scan(tmpDir);
      expect(result.scanner).toBe('Agent Config Auditor');
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some(f => f.severity === 'critical')).toBe(true);
    });

    it('should scan config.json files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.json'),
        JSON.stringify({
          gateway: { bind: '0.0.0.0', port: 8080 },
        })
      );

      const result = await agentConfigAuditor.scan(tmpDir);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should scan auth-profiles.json files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'auth-profiles.json'),
        JSON.stringify({
          gateway: { port: 18789, bind: '0.0.0.0' },
          apiKey: 'sk-ant-api03-realKeyHereThatIsVeryLong1234567890',
        })
      );

      const result = await agentConfigAuditor.scan(tmpDir);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should ignore non-config files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({ name: 'test', version: '1.0.0' })
      );

      const result = await agentConfigAuditor.scan(tmpDir);
      expect(result.findings.length).toBe(0);
    });

    it('should scan config.yaml files', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'config.yaml'),
        `gateway:
  bind: "0.0.0.0"
  port: 18789
channels:
  - name: telegram
    dmPolicy: open
`
      );

      const result = await agentConfigAuditor.scan(tmpDir);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some(f => f.title === 'Gateway exposed to network')).toBe(true);
    });
  });
});
