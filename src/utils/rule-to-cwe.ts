/**
 * Maps scanner rule IDs to CWE numbers.
 * Used by the CycloneDX formatter to enrich vulnerability entries.
 */

export const RULE_TO_CWE: Record<string, Record<string, number[]>> = {
  'prompt-injection-tester': {
    // Covers PI-001 through PI-088+ (INJECTION_PATTERNS)
    // Wildcard entry applied when specific rule not matched
    '*': [77, 1336],
  },

  'secret-leak-scanner': {
    'SL-001': [798, 259],
    'SL-013': [798, 259],
    'SL-014': [798, 259],
    'SP-001': [798],
    'SP-002': [798],
    'SP-003': [798],
    // HC-* hardcoded credential patterns
    '*': [798, 259],
  },

  'supply-chain-scanner': {
    'SUPPLY-001': [506, 77],      // Obfuscated (Base64) commands / code injection
    'SUPPLY-002': [506, 78],      // Remote code execution
    'SUPPLY-003': [506],          // Known malicious IPs/domains
    'SUPPLY-004': [522, 506],     // Credential theft
    'SUPPLY-005': [319, 506],     // Data exfiltration
    'SUPPLY-006': [506],          // Persistence mechanisms
    'SUPPLY-007': [1395, 20],     // Typosquatted packages
    'SUPPLY-008': [1395],         // Suspicious URL-based deps
    'SUPPLY-009': [506],          // Dangerous setup.py patterns
    'SUPPLY-010': [1395],         // Known malicious MCP packages
    '*': [1395],
  },

  'rag-poisoning-scanner': {
    'rag-prompt-injection': [74, 77],
    'rag-system-leak': [74, 200],
    'rag-hidden-instructions': [74],
    'rag-repetition-attack': [74],
    'rag-context-manipulation': [74],
    '*': [74],
  },

  'visual-prompt-injection-scanner': {
    'VPI-001': [77, 1336, 20],
    'VPI-002': [77, 1336],
    'VPI-003': [77, 1336],
    'VPI-150': [77, 1336],
    'VPI-IMG-SUMMARY': [77, 1336],
    '*': [77, 1336],
  },

  'ide-rule-injection-scanner': {
    'IRI-001': [94],
    'IRI-002': [94],
    'IRI-003': [94],
    'IRI-004': [94],
    'IRI-005': [94],
    'IRI-006': [94],
    'IRI-007': [94],
    'IRI-008': [94],
    'IRI-009': [94, 200],   // Exfiltration via injected rule
    'IRI-010': [94, 200],
    'IRI-011': [94],        // Hidden text (zero-width chars)
    'IRI-012': [94],
    'IRI-013': [94],
    'IRI-014': [94],
    'IRI-015': [94, 200],
    'IRI-016': [94],
    'IRI-017': [94],
    'IRI-018': [94],
    '*': [94],
  },

  'mcp-tool-shadowing-detector': {
    'SHADOW-001': [345, 451],
    'SHADOW-002': [345, 451],
    'SHADOW-003': [345, 451],
    '*': [345],
  },

  'dns-icmp-tool-scanner': {
    'dns-icmp-tool-injection': [319, 78],
    '*': [319],
  },

  'clipboard-exfiltration-scanner': {
    'clipboard-exfiltration': [200, 319],
    '*': [200],
  },

  'postinstall-scanner': {
    'POSTINSTALL-001': [506],
    'POSTINSTALL-002': [506, 78],
    'POSTINSTALL-003': [506],
    'POSTINSTALL-004': [506],
    'POSTINSTALL-005': [506, 77],
    'POSTINSTALL-006': [506, 200],
    '*': [506],
  },

  'convention-squatting-scanner': {
    'SQUAT-001': [1395, 20],
    'SQUAT-002': [1395, 20],
    'SQUAT-003': [1395],
    'SQUAT-004': [1395, 20],
    '*': [1395, 20],
  },

  'a2a-security-scanner': {
    'A2A-001': [287],
    'A2A-001-empty': [287],
    'A2A-002': [287, 290],
    'A2A-003': [287, 319],
    'A2A-004': [319],
    'A2A-005': [319],
    'A2A-006': [345, 287],
    'A2A-007': [345],
    'A2A-009': [345, 20],
    'A2A-000': [287],
    '*': [345, 287],
  },
};

/**
 * Returns CWE numbers for a given scanner and optional rule ID.
 * Falls back to the scanner-level wildcard ('*') if the specific rule is not found.
 * Returns an empty array if the scanner is unknown.
 */
export function lookupCWE(scanner: string, rule?: string): number[] {
  const scannerMap = RULE_TO_CWE[scanner];
  if (!scannerMap) return [];

  if (rule && scannerMap[rule]) return scannerMap[rule];
  if (scannerMap['*']) return scannerMap['*'];
  return [];
}
