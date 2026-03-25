export { ScannerRegistry } from './scanner-registry';
export { SupplyChainScanner } from './scanners/supply-chain-scanner';
export { HygieneAuditor } from './scanners/hygiene-auditor';
export { DxtSecurityScanner } from './scanners/dxt-security-scanner';
export { VisualPromptInjectionScanner } from './scanners/visual-prompt-injection-scanner';
export { LangChainSerializationScanner } from './scanners/langchain-serialization-scanner';
export { AgenticFrameworkScanner } from './scanners/agentic-framework-scanner';
export { PostinstallScanner } from './scanners/postinstall-scanner';
export { ConventionSquattingScanner } from './scanners/convention-squatting-scanner';
export { clipboardExfiltrationScanner } from './scanners/clipboard-exfiltration-scanner';
export { agentConfigAuditor } from './scanners/agent-config-auditor';
export { channelSurfaceAuditor } from './scanners/channel-surface-auditor';
export { defenseAnalyzer } from './scanners/defense-analyzer';
export { dnsIcmpToolScanner } from './scanners/dns-icmp-tool-scanner';
export { environmentIsolationAuditor } from './scanners/environment-isolation-auditor';
export { mcpConfigAuditor } from './scanners/mcp-config-auditor';
export { permissionAnalyzer } from './scanners/permission-analyzer';
export { promptInjectionTester } from './scanners/prompt-injection-tester';
export { ragPoisoningScanner } from './scanners/rag-poisoning-scanner';
export { redTeamSimulator } from './scanners/red-team-simulator';
export { secretLeakScanner } from './scanners/secret-leak-scanner';
export { skillAuditor } from './scanners/skill-auditor';
export { tetoraConfigAuditor } from './scanners/tetora-config-auditor';
export { mcpToolManifestScanner } from './scanners/mcp-tool-manifest-scanner';
export { ideRuleInjectionScanner } from './scanners/ide-rule-injection-scanner';
export { mcpToolShadowingDetector } from './scanners/mcp-tool-shadowing-detector';
export { mcpToolResultInjectionScanner } from './scanners/mcp-tool-result-injection-scanner';
export { mcpGitCveScanner } from './scanners/mcp-git-cve-scanner';
export { a2aSecurityScanner } from './scanners/a2a-security-scanner';
export { npmAttestationScanner } from './scanners/npm-attestation-scanner';
export { mcpSamplingAbuseScanner } from './scanners/mcp-sampling-abuse-scanner';
export { githubToxicFlowScanner } from './scanners/github-toxic-flow-scanner';
export { walkFiles } from './utils/file-walker';
export * from './types';

import { ScannerRegistry } from './scanner-registry';
import { Scanner } from './types';
// Class-based scanners (Scanner interface)
import { SupplyChainScanner } from './scanners/supply-chain-scanner';
import { HygieneAuditor } from './scanners/hygiene-auditor';
import { DxtSecurityScanner } from './scanners/dxt-security-scanner';
import { VisualPromptInjectionScanner } from './scanners/visual-prompt-injection-scanner';
import { LangChainSerializationScanner } from './scanners/langchain-serialization-scanner';
import { AgenticFrameworkScanner } from './scanners/agentic-framework-scanner';
import { PostinstallScanner } from './scanners/postinstall-scanner';
import { ConventionSquattingScanner } from './scanners/convention-squatting-scanner';
// Module-based scanners (ScannerModule interface, compatible with Scanner)
import { agentConfigAuditor } from './scanners/agent-config-auditor';
import { channelSurfaceAuditor } from './scanners/channel-surface-auditor';
import { clipboardExfiltrationScanner } from './scanners/clipboard-exfiltration-scanner';
import { defenseAnalyzer } from './scanners/defense-analyzer';
import { dnsIcmpToolScanner } from './scanners/dns-icmp-tool-scanner';
import { environmentIsolationAuditor } from './scanners/environment-isolation-auditor';
import { mcpConfigAuditor } from './scanners/mcp-config-auditor';
import { permissionAnalyzer } from './scanners/permission-analyzer';
import { promptInjectionTester } from './scanners/prompt-injection-tester';
import { ragPoisoningScanner } from './scanners/rag-poisoning-scanner';
import { redTeamSimulator } from './scanners/red-team-simulator';
import { secretLeakScanner } from './scanners/secret-leak-scanner';
import { skillAuditor } from './scanners/skill-auditor';
import { tetoraConfigAuditor } from './scanners/tetora-config-auditor';
import { mcpToolManifestScanner } from './scanners/mcp-tool-manifest-scanner';
import { ideRuleInjectionScanner } from './scanners/ide-rule-injection-scanner';
import { mcpToolShadowingDetector } from './scanners/mcp-tool-shadowing-detector';
import { mcpToolResultInjectionScanner } from './scanners/mcp-tool-result-injection-scanner';
import { mcpGitCveScanner } from './scanners/mcp-git-cve-scanner';
import { a2aSecurityScanner } from './scanners/a2a-security-scanner';
import { npmAttestationScanner } from './scanners/npm-attestation-scanner';
import { mcpSamplingAbuseScanner } from './scanners/mcp-sampling-abuse-scanner';
import { githubToxicFlowScanner } from './scanners/github-toxic-flow-scanner';

export function createDefaultRegistry(externalIOCPath?: string): ScannerRegistry {
  const registry = new ScannerRegistry();

  // Class-based scanners
  registry.register(new SupplyChainScanner(externalIOCPath));
  registry.register(new HygieneAuditor());
  registry.register(new DxtSecurityScanner());
  registry.register(new VisualPromptInjectionScanner());
  registry.register(new LangChainSerializationScanner());
  registry.register(new AgenticFrameworkScanner());
  registry.register(npmAttestationScanner as unknown as Scanner);
  registry.register(new PostinstallScanner());
  registry.register(new ConventionSquattingScanner());

  // Module-based scanners (cast to Scanner — structurally compatible)
  registry.register(agentConfigAuditor as unknown as Scanner);
  registry.register(channelSurfaceAuditor as unknown as Scanner);
  registry.register(clipboardExfiltrationScanner as unknown as Scanner);
  registry.register(defenseAnalyzer as unknown as Scanner);
  registry.register(dnsIcmpToolScanner as unknown as Scanner);
  registry.register(environmentIsolationAuditor as unknown as Scanner);
  registry.register(mcpConfigAuditor as unknown as Scanner);
  registry.register(permissionAnalyzer as unknown as Scanner);
  registry.register(promptInjectionTester as unknown as Scanner);
  registry.register(ragPoisoningScanner as unknown as Scanner);
  registry.register(redTeamSimulator as unknown as Scanner);
  registry.register(secretLeakScanner as unknown as Scanner);
  registry.register(skillAuditor as unknown as Scanner);
  registry.register(tetoraConfigAuditor as unknown as Scanner);
  registry.register(mcpToolManifestScanner as unknown as Scanner);
  registry.register(ideRuleInjectionScanner as unknown as Scanner);
  registry.register(mcpToolShadowingDetector as unknown as Scanner);
  registry.register(mcpToolResultInjectionScanner as unknown as Scanner);
  registry.register(mcpGitCveScanner as unknown as Scanner);
  registry.register(a2aSecurityScanner as unknown as Scanner);
  registry.register(mcpSamplingAbuseScanner as unknown as Scanner);
  registry.register(githubToxicFlowScanner as unknown as Scanner);

  return registry;
}
