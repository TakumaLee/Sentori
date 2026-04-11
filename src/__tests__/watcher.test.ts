import { getAffectedScanners, ChangeType } from '../watcher';

describe('getAffectedScanners', () => {
  it('returns null for config changes (re-run all scanners)', () => {
    expect(getAffectedScanners('config')).toBeNull();
  });

  it('returns package-related scanners for package changes', () => {
    const result = getAffectedScanners('package');
    expect(result).not.toBeNull();
    expect(result).toContain('Supply Chain Scanner');
    expect(result).toContain('NPM Attestation Scanner');
    expect(result).toContain('Postinstall Scanner');
    expect(result).toContain('Convention Squatting Detector');
    expect(result).toHaveLength(4);
  });

  it('returns MCP-related scanners for mcp changes', () => {
    const result = getAffectedScanners('mcp');
    expect(result).not.toBeNull();
    expect(result).toContain('MCP Config Auditor');
    expect(result).toContain('MCP Tool Manifest Scanner');
    expect(result).toContain('MCP Tool Shadowing Detector');
    expect(result).toContain('MCP OAuth Auditor');
    expect(result).toContain('MCP Git CVE Scanner');
    expect(result).toContain('MCP Sampling Abuse Scanner');
    expect(result).toContain('MCP Tool Result Injection Scanner');
    expect(result).toHaveLength(7);
  });
});
