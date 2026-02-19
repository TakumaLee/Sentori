# QA Review — Phase 1-3 (5ee1770..a0358a4)

**Reviewer:** Sentori QA Review Team
**Date:** 2026-02-04
**Scope:** 27 files, +3,733 lines across 5 commits

---

## 1. Issues Found (by severity)

### CRITICAL — Must fix before release

#### C1. `--include-vendored` flag is dead code
**File:** `src/cli.ts:53`, `src/index.ts`, `src/utils/file-utils.ts:76`

The CLI flag `--include-vendored` is defined in Commander and added to `ScanOptions`, and `buildIgnoreList()` accepts an `includeVendored` parameter. But `findFiles()` at `file-utils.ts:165` calls `buildIgnoreList(excludePatterns)` **without passing `includeVendored`**. The option is never threaded through from `runScan()` → scanners → `findFiles()`.

**Impact:** Users who pass `--include-vendored` get no effect. Vendored dirs are always excluded.

**Fix:** Thread `includeVendored` through `ScanOptions` → scanner options → `findFiles()` → `buildIgnoreList()`. Alternatively, store it in a module-level config or pass it via `ScanContext`.

---

#### C2. `isDefensePatternFile()` false-negative: Signal 4 has no threshold
**File:** `src/scanners/prompt-injection-tester.ts:197-210`

Signal 4 (`pathIsDefensive`) returns `true` for ANY file whose path contains words like `security`, `filter`, `guard`, `protect`, etc. This means a file named `security-config.json` with actual injection payloads would be silently downgraded to `info`.

More critically, an attacker could name a malicious file `defense-blocklist.json` or place payloads in a `security/` directory to bypass prompt injection scanning entirely.

**Impact:** Potential scan bypass via filename/path manipulation.

**Fix:** Signal 4 should require at least one additional signal (e.g., `pathIsDefensive && matchedCategories.size > 2`) rather than being sufficient on its own.

---

### HIGH — Should fix before release

#### H1. `isSecurityToolFile()` is too broad
**File:** `src/utils/file-utils.ts:149-152`

The regex matches any filename containing `scanner`, `analyzer`, `checker`, `monitor`, etc. A malicious file named `my-scanner.ts` that reads `/etc/passwd` for exfiltration would get its findings downgraded to `info`.

**Impact:** Attacker can name a file to evade skill auditor credential-read detection.

**Fix:** Combine with content-based heuristics (e.g., file must also import security-related libraries or contain multiple detection patterns).

---

#### H2. `isSentoriSourceFile()` matches any project with "sentori" in path
**File:** `src/utils/file-utils.ts:140-142`

The regex `/sentori[/\\]src[/\\]/i` matches any path containing `sentori/src/`, not just Sentori's own repo. If a user has a project inside a directory named `sentori` (e.g., `~/projects/sentori-demo/src/malicious.ts`), findings would be incorrectly downgraded.

Same applies to `isSentoriTestFile()`.

**Impact:** False negatives for projects with "sentori" in their path.

**Fix:** Check if the file is within the **running** Sentori installation directory (use `__dirname` or a build-time constant), not just any path matching the pattern.

---

#### H3. `isCacheOrDataFile()` matches `/data/` too broadly
**File:** `src/utils/file-utils.ts:91-103`

The pattern `/[/\\]data[/\\]/i` matches any file inside a `data/` directory. Many real projects use `src/data/`, `app/data/`, etc. for actual application data files that may contain MCP configs or permissions.

**Impact:** Real config files inside `data/` directories get silently downgraded.

**Fix:** Make the pattern more specific — require `data` to be at the project root level, or require additional context (e.g., path also contains `cache`, `crawl`, etc.).

---

#### H4. `TOOL_CONFIG_KEYS` in permission-analyzer includes overly generic keys
**File:** `src/scanners/permission-analyzer.ts:416-431`

Keys like `model`, `command`, `args`, `env`, `endpoint`, `api`, `functions` are extremely common in non-agent configs. A standard Docker Compose file has `command`, `args`, `env`. A webpack config has `plugins`. This reduces the effectiveness of the `isToolOrMcpConfig()` gate.

**Impact:** The intent was to skip non-tool configs, but the check is so broad that nearly any config passes.

**Fix:** Require at least 2 matching keys, or weight MCP-specific keys (like `mcpServers`, `allowedPaths`) higher than generic ones.

---

#### H5. Weakest-link dimension scoring is fragile for future scanners
**File:** `src/utils/scorer.ts:28-37`

`DIMENSION_MAP` hardcodes all 8 current scanners. If a new scanner is added without updating this map, its findings won't contribute to any dimension score but will still affect the overall penalty. The `hasAnyDimensionFindings` check could also produce inconsistent results.

**Impact:** Silent scoring bugs when scanners are added.

**Fix:** Add a runtime check: if `result.scanner` is not in `DIMENSION_MAP`, log a warning or throw. Alternatively, default unmapped scanners to a dimension.

---

### MEDIUM — Should fix, not blocking

#### M1. Confidence assignment is blanket per-scanner, not per-finding
**File:** All scanners (`for (const f of findings) f.confidence = '...'`)

Every scanner sets the same confidence on ALL its findings. E.g., `Prompt Injection Tester` sets `definite` on everything, even heuristic downgrades. `Defense Analyzer` sets `possible` on everything, even concrete "API key found in prompt" findings.

**Impact:** Confidence weighting is less useful than it could be — it's effectively a per-scanner weight, not a per-finding assessment.

**Fix:** Set confidence at finding creation time based on the evidence quality (e.g., regex match on actual secret = `definite`, missing defense = `possible`). This is an enhancement, not a bug.

---

#### M2. Repeated severity-downgrade boilerplate across scanners
**File:** `prompt-injection-tester.ts`, `secret-leak-scanner.ts`, `skill-auditor.ts`, `defense-analyzer.ts`

The same 6-line pattern appears 5+ times:
```ts
if (isSentoriTestFile(file)) {
  for (const f of fileFindings) {
    if (f.severity !== 'info') {
      f.severity = 'info';
      f.description += ' [security tool test file — ...]';
    }
  }
}
```

**Impact:** Code duplication. A change to downgrade logic must be made in 5+ places.

**Fix:** Extract a shared `applyContextDowngrades(findings, file)` utility.

---

#### M3. `isDefensePatternFile()` Signal 3 threshold (>5 categories) may be too low
**File:** `src/scanners/prompt-injection-tester.ts:195-207`

A sufficiently complex legitimate prompt file (e.g., a security training document) could match 6+ injection categories and be incorrectly classified as a defense pattern list.

**Impact:** Legitimate security-related content could be silently downgraded.

**Fix:** Raise threshold to 8+ or combine with other signals.

---

#### M4. `permission-analyzer.ts` double-parses JSON/YAML
**File:** `src/scanners/permission-analyzer.ts:56-62` and `:77-82`

For JSON/YAML files, `analyzePermissions()` parses the file, then `analyzeToolPermissionBoundaries()` re-parses it to check `isToolOrMcpConfig()`. This is a performance waste and could produce inconsistent results if parsing has side effects.

**Fix:** Parse once, pass the result.

---

#### M5. SP-003 regex rewrite may miss edge cases
**File:** `src/patterns/injection-patterns.ts:1059`

The new `.env` pattern only matches:
- `.env.local`, `.env.production`, `.env.staging`, `.env.development`, `.env.test`
- `require/import/load/read/cat/source/cp/mv/rm` followed by `.env`
- `dotenv`

It no longer matches standalone `.env` mentions (the old pattern with `(?<!process)\.env\b` was broader). A line like `store secrets in .env` will only be caught by `isEnvProseMention()` logic in `secret-leak-scanner.ts`, not by the pattern itself.

**Impact:** Potential false negatives for non-standard `.env` references.

**Fix:** Verify with a broader set of real-world `.env` usage patterns.

---

#### M6. Channel surface auditor reads ALL source files into memory
**File:** `src/scanners/channel-surface-auditor.ts:345-352`

```ts
const allSourceContent = new Map<string, string>();
for (const file of sourceFiles) {
  allSourceContent.set(file, readFileContent(file));
}
```

This loads every `.ts/.js/.py/.sh` file into memory at once. For large projects, this could cause high memory usage.

**Fix:** Check code evidence lazily per-channel, or break once evidence is found for each channel.

---

### LOW / INFO

#### L1. `VENDORED_IGNORE` pattern `**/*.cpp/**` is wrong
**File:** `src/utils/file-utils.ts:56`

`**/*.cpp/**` would match any directory ending in `.cpp` (like `llama.cpp/`) but NOT individual `.cpp` source files. The intent seems correct (exclude repos like `llama.cpp`), but the glob `**/*.cpp/**` would also match `my-project.cpp/src/` which is unusual but possible.

**Fix:** The pattern works for the intended use case. Consider adding a comment clarifying intent.

---

#### L2. `interactionPenalty()` uses `Math.min(critical, high)` — this caps the interaction on the smaller count
**File:** `src/utils/scorer.ts:51-54`

With 10 critical and 1 high, the penalty is `5 * log2(2) = 5`. With 1 critical and 10 high, it's also 5. The rationale (compounding risk from multiple types) seems sound — interaction should scale with the bottleneck.

**Status:** Not a bug, but the choice should be documented.

---

#### L3. README.md needs updating
**File:** `README.md`

Missing documentation for:
- 3-dimension scoring (codeSafety / configSafety / defenseScore)
- Confidence levels (definite / likely / possible)
- `--include-vendored` flag
- Updated JSON output format with `dimensions` and `scannerBreakdown`

---

#### L4. Example output in tests doesn't cover `confidence` field consistently
Some test findings don't set `confidence`, relying on the `?? 'definite'` fallback in `weightedSeverityCounts()`. This is fine but means tests don't catch if a scanner forgets to set confidence.

---

## 2. Summary Table

| ID | Severity | Component | Description |
|----|----------|-----------|-------------|
| C1 | CRITICAL | CLI / file-utils | `--include-vendored` flag is dead code |
| C2 | CRITICAL | prompt-injection | `isDefensePatternFile` Signal 4 bypass |
| H1 | HIGH | file-utils | `isSecurityToolFile()` too broad |
| H2 | HIGH | file-utils | `isSentoriSourceFile()` matches non-self paths |
| H3 | HIGH | file-utils | `isCacheOrDataFile()` `/data/` too broad |
| H4 | HIGH | permission-analyzer | `TOOL_CONFIG_KEYS` too generic |
| H5 | HIGH | scorer | `DIMENSION_MAP` fragile for new scanners |
| M1 | MEDIUM | all scanners | Blanket confidence per-scanner |
| M2 | MEDIUM | all scanners | Duplicated downgrade boilerplate |
| M3 | MEDIUM | prompt-injection | Defense pattern threshold too low |
| M4 | MEDIUM | permission-analyzer | Double JSON/YAML parsing |
| M5 | MEDIUM | injection-patterns | SP-003 regex may miss edge cases |
| M6 | MEDIUM | channel-auditor | Loads all source files into memory |
| L1 | LOW | file-utils | `*.cpp/**` glob intent unclear |
| L2 | LOW | scorer | `interactionPenalty` design choice |
| L3 | LOW | README | Missing documentation for new features |
| L4 | LOW | tests | Confidence field not tested at creation |

---

## 3. Positive Observations

- **Test coverage is strong:** 760 tests, 90%+ line coverage, comprehensive FP regression tests
- **Architecture is clean:** Scanner → Finding → Scorer pipeline is well-structured
- **Context-awareness is thoughtful:** app/framework/skill contexts, test/doc downgrades
- **Scoring math is correct:** Diminishing returns, confidence weighting, interaction penalty all compute correctly
- **Channel auditor code evidence** is a good design — requiring actual imports, not just keyword mentions

---

## 4. Conclusion

### Can it ship?

**Not yet.** Fix C1 and C2 first:

1. **C1 (`--include-vendored` dead code):** Either wire it through or remove the flag. Shipping a documented but non-functional flag erodes user trust.

2. **C2 (`isDefensePatternFile` Signal 4):** An attacker placing files in a `security/` directory bypasses injection scanning. This is a real scan-bypass vector.

After those two fixes, the HIGH issues (H1-H5) should be addressed in a follow-up release. They represent defense-in-depth concerns but are not easily exploitable in typical scanning scenarios.

### Recommended release sequence

1. **Hotfix (block release):** C1, C2
2. **v0.2.0 (next minor):** H1-H5, M2 (code dedup)
3. **v0.3.0 (enhancement):** M1 (per-finding confidence), L3 (README update)
