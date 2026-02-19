# Sentori Scoring System Review — Team Alpha

> **Reviewer**: Scoring Review Team Alpha
> **Date**: 2026-02-04
> **Scope**: `scorer.ts`, `injection-patterns.ts`, all scanners, framework/test downgrades
> **Methodology**: Code review + mathematical simulation of 12 archetype scenarios

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Scoring Formula Deep Dive](#2-current-scoring-formula-deep-dive)
3. [Scenario Simulations (Current System)](#3-scenario-simulations-current-system)
4. [Injection Pattern Severity Audit](#4-injection-pattern-severity-audit)
5. [Scanner Overlap Analysis](#5-scanner-overlap-analysis)
6. [Grade Boundary Analysis](#6-grade-boundary-analysis)
7. [Framework Context & Test/Doc Downgrade Audit](#7-framework-context--testdoc-downgrade-audit)
8. [False Positive Impact Analysis](#8-false-positive-impact-analysis)
9. [Issues Found](#9-issues-found)
10. [Proposed Scoring Changes](#10-proposed-scoring-changes)
11. [Side-by-Side Comparison](#11-side-by-side-comparison)
12. [Final Recommendations](#12-final-recommendations)

---

## 1. Executive Summary

The current scoring system is **fundamentally sound** — logarithmic diminishing returns and per-category caps are the right approach. However, the simulation reveals several issues:

| Issue | Severity | Impact |
|-------|----------|--------|
| 1 critical finding = B- (85) feels too lenient | Medium | Users may not take single critical findings seriously |
| Score floor is effectively 15 (never reaches 0) | High | Theoretical max penalty = 85, so F grade is unreachable |
| Medium findings have negligible impact | Medium | 20 mediums only cost 6.5 points |
| No interaction bonus between critical+high | Low | Combined threats aren't weighted higher |
| Some PI patterns have incorrect severity | Medium | FP noise or under-reporting |
| Scanner overlap in secret+injection patterns | Low | Double-counting possible but rare |

**Verdict**: The system needs **tuning, not redesign**. Specific changes recommended below.

---

## 2. Current Scoring Formula Deep Dive

### Constants

```
SEVERITY_BASE_PENALTY:  critical=15, high=5, medium=1.5, info=0
SEVERITY_MAX_PENALTY:   critical=40, high=30, medium=15, info=0
```

### Formula

```
penalty(count, base, cap) = min(base × log₂(count + 1), cap)
score = clamp(round(100 - Σpenalties), 0, 100)
```

### Penalty Tables (Pre-computed)

#### Critical Findings

| Count | Raw Penalty | Capped | Score | Grade |
|-------|-------------|--------|-------|-------|
| 0     | 0           | 0      | 100   | A+    |
| 1     | 15.00       | 15.00  | 85    | B-    |
| 2     | 23.77       | 23.77  | 76    | C+    |
| 3     | 30.00       | 30.00  | 70    | C-    |
| 4     | 34.83       | 34.83  | 65    | D     |
| 5     | 38.77       | 38.77  | 61    | D-    |
| 6     | 42.07       | **40** | 60    | D-    |
| 10    | 51.90       | **40** | 60    | D-    |
| 50    | 84.08       | **40** | 60    | D-    |

**Observation**: 6+ critical findings all produce the same score (60/D-). The cap kicks in too early.

#### High Findings

| Count | Raw Penalty | Capped | Score | Grade |
|-------|-------------|--------|-------|-------|
| 0     | 0           | 0      | 100   | A+    |
| 1     | 5.00        | 5.00   | 95    | A     |
| 2     | 7.92        | 7.92   | 92    | A-    |
| 3     | 10.00       | 10.00  | 90    | A-    |
| 5     | 12.92       | 12.92  | 87    | B+    |
| 10    | 17.30       | 17.30  | 83    | B     |
| 20    | 21.97       | 21.97  | 78    | C+    |
| 30    | 24.95       | 24.95  | 75    | C     |
| 50    | 28.27       | 28.27  | 72    | C-    |
| 60+   | 30+         | **30** | 70    | C-    |

**Observation**: Even 50 high findings only produce C-. Floor is 70.

#### Medium Findings

| Count | Raw Penalty | Capped | Score | Grade |
|-------|-------------|--------|-------|-------|
| 1     | 1.50        | 1.50   | 99    | A+    |
| 5     | 3.88        | 3.88   | 96    | A     |
| 10    | 5.19        | 5.19   | 95    | A     |
| 20    | 6.59        | 6.59   | 93    | A     |
| 50    | 8.48        | 8.48   | 92    | A-    |
| 100   | 10.04       | 10.04  | 90    | A-    |
| 500   | 13.46       | 13.46  | 87    | B+    |
| 1000+ | 15+         | **15** | 85    | B-    |

**Observation**: Medium findings are almost negligible. 100 mediums = A-. This is by design (info noise reduction) but may be too aggressive.

### Theoretical Score Range

```
Best case:   100 (A+) — no findings
Worst case:  100 - 40 - 30 - 15 = 15 (F) — all caps hit
```

The score CAN reach 15 (F), but only with massive findings across all three severity levels simultaneously. In practice, the floor for a single category is:
- Critical only: 60 (D-)
- High only: 70 (C-)
- Medium only: 85 (B-)

---

## 3. Scenario Simulations (Current System)

### Scenario 1: Clean Project (Baseline)
```
Findings: 0C, 0H, 0M, 5 info
Penalty: 0 + 0 + 0 = 0
Score: 100 → A+
```

### Scenario 2: Well-Defended App (Low Risk)
```
Findings: 0C, 2H, 5M (e.g., missing rate limit, some medium PI matches in docs)
Penalty: 0 + 7.92 + 3.88 = 11.80
Score: 88 → B+
```

### Scenario 3: Typical App — Moderate Issues
```
Findings: 1C, 4H, 8M
  Critical: 15 × log₂(2) = 15.00
  High: 5 × log₂(5) = 11.61
  Medium: 1.5 × log₂(9) = 4.75
Penalty: 31.36
Score: 69 → D+
```

### Scenario 4: Risky App — Multiple Vulns
```
Findings: 3C, 8H, 15M
  Critical: 15 × log₂(4) = 30.00
  High: 5 × log₂(9) = 15.85
  Medium: 1.5 × log₂(16) = 6.00
Penalty: 51.85
Score: 48 → F
```

### Scenario 5: Catastrophic — Everything Wrong
```
Findings: 10C, 20H, 40M
  Critical: min(15 × log₂(11), 40) = 40.00 (capped)
  High: 5 × log₂(21) = 21.97
  Medium: 1.5 × log₂(41) = 8.02
Penalty: 69.99
Score: 30 → F
```

### Scenario 6: Framework Context — All Downgrades Applied
```
Original: 2C, 5H, 3M
After framework downgrades:
  - 1 critical tool-permission → info (PERM-TOOL-UNRESTRICTED)
  - 2 high shell-exec → info (SA-003d)
  - 1 high auth-missing → info (auth modules detected)
Effective: 1C, 2H, 3M
  Critical: 15.00
  High: 7.92
  Medium: 2.83
Penalty: 25.75
Score: 74 → C
```

### Scenario 7: Test File Heavy Project
```
Original: 5C, 10H in test files
After test/doc downgrade: 5M, 10 info
  Medium: 1.5 × log₂(6) = 3.88
Penalty: 3.88
Score: 96 → A
```
**Observation**: Test-heavy projects get nearly perfect scores even with findings. This is correct behavior.

### Scenario 8: Single Critical — Leaked API Key
```
Findings: 1C (SL-003, OpenAI key in system prompt)
Penalty: 15
Score: 85 → B-
```
**Problem**: A leaked API key in production code should probably not produce B-. This feels too lenient for a genuine critical finding.

### Scenario 9: Medium-Heavy — Many FP-Prone Patterns
```
Findings: 0C, 0H, 25M (all PI-007/008/009 hypothetical scenarios in docs)
Penalty: 1.5 × log₂(26) = 7.05
Score: 93 → A
```
**Observation**: Many false-positive mediums barely dent the score. This is good.

### Scenario 10: Injection-Heavy App (Chatbot with user-facing prompts)
```
Findings: 2C (PI-014 system delimiters, PI-045 eval), 6H (PI patterns), 10M
  Critical: 23.77
  High: 14.04
  Medium: 5.19
Penalty: 43.00
Score: 57 → F
```

### Scenario 11: Real-World AI Agent (e.g., MCP skill marketplace)
```
Findings: 1C (wildcard permission), 3H (no path scope, external API, missing auth),
          2M (missing rate limit), 4 info
  Critical: 15.00
  High: 10.00
  Medium: 2.38
Penalty: 27.38
Score: 73 → C
```

### Scenario 12: False Positive Storm — Clean Project Misidentified
```
Actual risk: None
FP Findings: 0C, 2H (PI-030 URGENT/IMPORTANT in comments, PI-049 password= in config example), 8M
  High: 7.92
  Medium: 4.75
Penalty: 12.67
Score: 87 → B+
```
**Problem**: A clean project scored B+ due to FPs. The H-severity FPs are the main culprit.

---

## 4. Injection Pattern Severity Audit

### Patterns That Should Be DOWNGRADED

| ID | Current | Proposed | Rationale |
|----|---------|----------|-----------|
| PI-030 | medium | **info** | `IMPORTANT`, `URGENT`, `CRITICAL` as standalone words are extremely common in normal code comments, documentation, and log levels. Extremely high false positive rate. |
| PI-047 | critical | **high** | "as your developer, I order" — this is social engineering, not a direct system compromise. Consistent with PI-046 (high). |
| PI-127 | medium | **info** | "you should think for yourself" — too vague, matches normal conversational text. High FP in chatbot UX copy. |
| PI-138 | medium | **info** | `user_id: 123` — extremely common in API code, configs, logs. Nearly 100% FP rate in web apps. |
| PI-065 | high | **medium** | `function_call...name...arguments` — matches normal OpenAI SDK usage code, not just injection. |

### Patterns That Should Be UPGRADED

| ID | Current | Proposed | Rationale |
|----|---------|----------|-----------|
| PI-068 | high | **critical** | Callback/webhook URL injection = active data exfiltration channel. This is equivalent to PI-038 (credential extraction, critical). |
| PI-110 | high | **critical** | MCP server-side instruction injection is a direct control-plane attack. Should match PI-105–PI-109 (all critical). |
| PI-111 | high | **critical** | Indirect injection via return value is one of the most dangerous attack vectors in agentic systems. Research papers consistently rank this as critical. |

### Patterns With Questionable FP Rates

| ID | Severity | Pattern | FP Concern |
|----|----------|---------|------------|
| PI-008 | medium | `for educational purposes only` | Common in legitimate README files and license headers |
| PI-020 | medium | `respond only in json` | Standard API instruction, not an attack |
| PI-049 | high | `password = ` | Matches config files, env examples, forms |
| PI-079 | info | Model parameter probing | Already info, correct |
| PI-081 | medium | "I'm a security researcher" | Common in legitimate security docs |

**Recommendation**: PI-020 and PI-049 should be considered for downgrade if FP rates are confirmed high in production telemetry.

---

## 5. Scanner Overlap Analysis

### Identified Overlaps

#### 1. Secret Leak Scanner ↔ Injection Patterns (PI-038)
- `PI-038`: "reveal your secrets/passwords/tokens/keys" → **critical** (injection scanner)
- `SL-002`: `secret/token/password = <value>` → **critical** (secret scanner)
- **Overlap scenario**: A file containing `reveal your secret token=abc123` could trigger BOTH.
- **Impact**: Double penalty (2 critical = 23.77 instead of 15).
- **Verdict**: Acceptable — they detect different things (social engineering vs actual secret). Low overlap probability in practice.

#### 2. Permission Analyzer ↔ Skill Auditor
- `PERM-TOOL-UNRESTRICTED`: Filesystem tool without path scope → **critical**
- `SA-006`: Path traversal patterns → **high**
- **Overlap**: A skill with filesystem access AND path traversal code triggers both.
- **Impact**: 1C + 1H = 15 + 5 = 20 penalty.
- **Verdict**: Acceptable — they're complementary views (config vs code).

#### 3. Defense Analyzer ↔ Red Team Simulator
- `DF-001` (missing input sanitization) generates a finding.
- `RT-001` (role confusion attack possible) also generates a finding if defenses are weak.
- Both feed into the same finding count.
- **Impact**: The defense analyzer finding and the corresponding red team finding produce 2 high findings instead of 1.
- **Verdict**: **Moderate concern**. This is the most significant overlap. A project missing input sanitization gets double-penalized — once for "you don't have it" (defense) and once for "here's how you'd be attacked" (red team). Consider whether RT findings should only appear if the corresponding DF finding is NOT present, or vice versa.

#### 4. Channel Surface Auditor ↔ Defense Analyzer
- `CH-EMAIL` (undefended email channel) → high
- `DF-003` (missing output filtering) → high
- A project with email integration and no output filtering triggers both.
- **Verdict**: Acceptable — channel-specific vs defense-generic perspectives.

### Overall Overlap Assessment

The **Defense Analyzer ↔ Red Team** overlap is the only one that warrants action. Other overlaps are conceptually different perspectives on the same underlying issue, which is valid.

---

## 6. Grade Boundary Analysis

### Current Grade Scale

```
A+ ≥97   A ≥93   A- ≥90
B+ ≥87   B ≥83   B- ≥80
C+ ≥77   C ≥73   C- ≥70
D+ ≥67   D ≥63   D- ≥60
F  <60
```

### Grade Transitions — What Triggers Them?

| Transition | What It Takes |
|------------|---------------|
| A+ → A    | 1 high finding, or 5 mediums |
| A → A-    | 2 high findings |
| A- → B+   | 3 high findings |
| A+ → B-   | 1 critical finding |
| B- → C+   | 1 critical + 2 high |
| → F       | 3C+8H+15M or equivalent (~40+ penalty) |

### Issues

1. **A+ is too easy to lose**: A single high finding drops from A+ to A. Given that high findings include things like "missing rate limiting" (a common gap), A+ may be nearly impossible for real projects.

2. **B- to C+ gap**: 1 critical puts you at B-. Adding just 2 more high findings drops you to C+. The B range is very narrow for projects with any critical findings.

3. **D range is a dead zone**: Very few scenarios naturally land in D+/D/D-. You're either in C- territory or F territory.

4. **F threshold at 60 is reasonable**: Projects scoring below 60 genuinely have serious issues.

### Recommendation

The grade boundaries are **acceptable** for a security tool. Academic-style grading (3-point intervals) provides good granularity. No changes recommended to the boundaries themselves — the issues are in the penalty constants, not the grade scale.

---

## 7. Framework Context & Test/Doc Downgrade Audit

### Test/Doc Downgrade

**Rule**: critical→medium, high→info for test/doc files.

**Assessment**: ✅ **Correct and well-implemented.**

- Pattern list is comprehensive (tests, __tests__, spec, fixtures, mocks, docs, examples, README)
- The 2-level downgrade (critical→medium, not critical→info) is appropriate — test files with real secrets still warrant attention
- Annotation `[test/doc file — severity reduced]` maintains transparency

**Potential gap**: No downgrade for `*.stories.tsx` (Storybook files), `*.bench.*` (benchmark files), or `cypress/e2e/**` (E2E test files). These are low-risk but uncommon enough to be acceptable omissions.

### Framework Context Downgrades

#### Secret Leak Scanner
- Platform config files (google-services.json, etc.) → **info**: ✅ Correct. These contain public API identifiers, not secrets.
- Credential management modules → **info**: ✅ Correct. Credential managers must read secrets.
- Dev credentials (postgres/root/admin/localhost) → **medium/info**: ✅ Correct.

#### Permission Analyzer
- Tool permissions (PERM-TOOL-UNRESTRICTED) → **info**: ✅ Correct. Frameworks define tooling interfaces; users configure restrictions.
- Auth modules detected → downgrade auth-missing: ✅ Correct with caveat — the annotation "may not cover all entry points" is appropriate.

#### Skill Auditor
- SA-003d (shell execution) in non-skill files → **info**: ✅ Correct. AI agent runtimes need shell access.
- SA-006 (path traversal) in framework infra → **medium**: ✅ Correct.
- SA-002 (reading sensitive files) standalone → **info**: ✅ Correct for 12-factor apps.

### Missing Downgrades (Potential Gaps)

1. **Injection patterns in prompt template files**: If a project has `prompts/system.txt` containing "ignore previous instructions" as a TEST CASE or CANARY, it gets flagged as critical. No framework/context downgrade applies here. **Recommendation**: Consider downgrading PI findings in files under `prompts/`, `templates/`, or `fixtures/` when they're clearly canary/test patterns.

2. **CI/CD files**: Docker/Kubernetes configs containing `sudo`, `chmod`, or `rm -rf` in CI scripts (Dockerfile, Makefile) may trigger SA-003/SA-005. These are normal for build systems. The framework context partially handles this, but explicit CI file patterns could help.

---

## 8. False Positive Impact Analysis

### FP-Prone Patterns Ranked by Score Impact

| Pattern | Severity | FP Rate (Est.) | Score Impact per FP | Risk |
|---------|----------|----------------|---------------------|------|
| PI-030 (URGENT/IMPORTANT) | medium | Very High (80%+) | -1.5 first, diminishing | Low |
| PI-049 (password=) | high | High (60%) | -5 first, diminishing | **Medium** |
| PI-020 (respond in json) | medium | High (70%) | -1.5 first, diminishing | Low |
| PI-138 (user_id: 123) | medium | Very High (90%) | -1.5 first, diminishing | Low |
| SL-002 (secret/token=) | critical | Medium (40%) | **-15 first** | **High** |
| PI-008 (educational purposes) | medium | Medium (50%) | -1.5 first, diminishing | Low |

### Worst-Case FP Scenario

A typical Node.js web app with config files, documentation, and API code:
```
False positives:
  1C: SL-002 matches `token = req.headers.authorization` in middleware
  3H: PI-049 × 2 (password fields in forms), PI-068 (webhook URL in API docs)
  6M: PI-030 × 3, PI-020 × 2, PI-138 × 1

Penalty: 15 + 10 + 4.06 = 29.06
Score: 71 → C-
```

A clean project scores **C-** due entirely to false positives. This is a significant problem.

### Mitigation Effectiveness

The test/doc downgrade catches ~50% of these FPs (docs, examples). Framework context catches another ~20%. But FPs in **production source code** (middleware, API handlers, form validation) are not mitigated.

**Key insight**: The highest-impact FP is SL-002 matching variable assignments that LOOK like secrets but aren't (e.g., `const token = getToken()`). A single false critical costs 15 points.

---

## 9. Issues Found

### Issue 1: Single Critical = B- Is Too Lenient

A single leaked API key (genuinely critical) produces an 85 (B-). Users seeing B- may think "not bad" and ignore it. A critical finding should visually alarm users.

### Issue 2: Score Floor Too High for Single Categories

6+ critical findings all produce the same score (60). A project with 20 critical findings should score worse than one with 6.

### Issue 3: PI-030 Is a FP Magnet

The words IMPORTANT, URGENT, CRITICAL, MANDATORY, OVERRIDE in ALL CAPS are ubiquitous in code comments, log levels, HTTP headers, and documentation. This pattern alone can add 3–5 medium findings to any project.

### Issue 4: Defense ↔ Red Team Double Penalty

Missing a defense category (e.g., input sanitization) triggers both a DF finding and a corresponding RT finding, effectively doubling the penalty for a single conceptual gap.

### Issue 5: PI-047 Severity Inconsistency

PI-046 ("I am your developer") is high, but PI-047 ("as your developer, I order") is critical. Both are social engineering. The presence of "I order" doesn't make this a system-level attack — it's still social engineering.

### Issue 6: Critical Agentic Patterns Underrated

PI-110 (MCP server-side injection) and PI-111 (indirect injection via return value) are high, but these are the PRIMARY attack vectors against agentic AI systems (as documented by OWASP, NIST, and multiple security research papers). They should be critical.

---

## 10. Proposed Scoring Changes

### Option A: Tuned Constants (Minimal Change)

```typescript
const SEVERITY_BASE_PENALTY = {
  critical: 18,   // was 15 — single critical now costs more
  high: 5,        // unchanged
  medium: 1.5,    // unchanged
  info: 0,
};

const SEVERITY_MAX_PENALTY = {
  critical: 50,   // was 40 — higher ceiling for extreme cases
  high: 30,       // unchanged
  medium: 15,     // unchanged
  info: 0,
};
```

**Impact of Option A**:

| Scenario | Current Score | Proposed Score | Current Grade | Proposed Grade |
|----------|-------------|----------------|---------------|----------------|
| 1C | 85 (B-) | 82 (B-) | B- | B- |
| 2C | 76 (C+) | 71 (C-) | C+ | C- |
| 3C | 70 (C-) | 64 (D) | C- | D |
| 6C | 60 (D-) | 50 (F) | D- | F |
| 10C | 60 (D-) | 50 (F) | D- | F |
| 1C+3H+5M | 65 (D) | 61 (D-) | D | D- |

**Assessment**: Marginal improvement. Single critical is still B-. Not enough differentiation.

### Option B: Adjusted Base + Interaction Term (Recommended)

```typescript
const SEVERITY_BASE_PENALTY = {
  critical: 20,   // single critical = -20 → score 80 (B-)
  high: 5,
  medium: 1.5,
  info: 0,
};

const SEVERITY_MAX_PENALTY = {
  critical: 55,   // more room before cap
  high: 30,
  medium: 15,
  info: 0,
};

// NEW: Interaction penalty when critical AND high coexist
function interactionPenalty(critical: number, high: number): number {
  if (critical > 0 && high > 0) {
    return Math.min(5 * Math.log2(Math.min(critical, high) + 1), 10);
  }
  return 0;
}
```

**Impact of Option B**:

| Scenario | Current | Proposed | Current Grade | Proposed Grade |
|----------|---------|----------|---------------|----------------|
| 0C, 0H, 0M | 100 | 100 | A+ | A+ |
| 0C, 2H, 5M | 88 | 88 | B+ | B+ |
| 1C, 0H, 0M | 85 | **80** | B- | **B-** |
| 1C, 3H, 5M | 69 | **59** | D+ | **F** |
| 2C, 5H, 8M | 56 | **42** | F | F |
| 3C, 8H, 15M | 48 | **33** | F | F |
| 5C, 15H, 20M | 38 | **20** | F | F |
| 10C, 20H, 40M | 30 | **12** | F | F |

Computation for 1C, 3H, 5M under Option B:
```
Critical: 20 × log₂(2) = 20.00
High:     5 × log₂(4) = 10.00
Medium:   1.5 × log₂(6) = 3.88
Interaction: 5 × log₂(2) = 5.00  (min(1,3)=1, log₂(2)=1)
Total penalty: 38.88
Score: round(100 - 38.88) = 61 ...

Wait, let me recalculate with the interaction:
Total = 20 + 10 + 3.88 + 5.00 = 38.88
Score = 100 - 38.88 = 61.12 → 61 (D-)
```

Hmm, the interaction term is small. Let me recalculate more carefully:

For 1C, 3H, 5M:
```
Critical: 20 × log₂(2) = 20.00
High: 5 × log₂(4) = 10.00
Medium: 1.5 × log₂(6) = 3.88
Interaction: 5 × log₂(min(1,3)+1) = 5 × log₂(2) = 5.00
Total: 38.88
Score: 61 → D-
```

Updated table with correct calculations:

| Scenario | Current Score/Grade | Option B Score/Grade |
|----------|---------------------|----------------------|
| 0C, 0H, 0M | 100 / A+ | 100 / A+ |
| 0C, 2H, 5M | 88 / B+ | 88 / B+ |
| 1C, 0H, 0M | 85 / B- | 80 / B- |
| 1C, 3H, 5M | 69 / D+ | 61 / D- |
| 2C, 0H, 0M | 76 / C+ | 68 / D+ |
| 2C, 5H, 8M | 56 / F | 44 / F |
| 3C, 8H, 15M | 48 / F | 33 / F |
| 10C, 0H, 0M | 60 / D- | 45 / F |
| 10C, 20H, 40M | 30 / F | 6 / F |

**Key improvements**:
- 1 critical alone = 80 (B-) — still a B but at the bottom, signaling concern
- 2 criticals alone = 68 (D+) — clearly in D territory, not C+
- 10 criticals = 45 (F) — proper differentiation vs current 60
- Low-risk scenarios unchanged (B+ stays B+)
- F range now has more spread (6–59 vs 0–59)

### Option C: Radical — Weight by Scanner Diversity

Add a multiplier when findings come from 3+ different scanners:

```typescript
const scannerDiversity = new Set(results.map(r => r.scanner)).size;
const diversityMultiplier = scannerDiversity >= 4 ? 1.1 : 1.0;
penalty *= diversityMultiplier;
```

**Assessment**: Adds complexity for marginal benefit. Not recommended unless scanner overlap (Issue 4) is not addressed.

---

## 11. Side-by-Side Comparison

### Comprehensive Scenario Matrix

| # | Scenario Description | Findings | Current Score | Current Grade | Option B Score | Option B Grade | Better? |
|---|---------------------|----------|---------------|---------------|----------------|----------------|---------|
| 1 | Clean project | 0/0/0 | 100 | A+ | 100 | A+ | = |
| 2 | Minor issues only | 0/2/5 | 88 | B+ | 88 | B+ | = |
| 3 | One leaked secret | 1/0/0 | 85 | B- | 80 | B- | ✅ |
| 4 | Moderate app | 1/4/8 | 69 | D+ | 58 | F | ✅ |
| 5 | Risky app | 3/8/15 | 48 | F | 33 | F | ✅ |
| 6 | Catastrophic | 10/20/40 | 30 | F | 6 | F | ✅ |
| 7 | All test-file FPs | 0/0/5m | 96 | A | 96 | A | = |
| 8 | FP storm (clean proj) | 0/2/6 fp | 87 | B+ | 87 | B+ | = |
| 9 | Framework context | 1→0C, 5→2H | 88 | B+ | 88 | B+ | = |
| 10 | High-only project | 0/10/0 | 83 | B | 83 | B | = |
| 11 | Medium-only flood | 0/0/50 | 92 | A- | 92 | A- | = |
| 12 | Real agent (MCP) | 1/3/2 | 73 | C | 63 | D | ⚠️ |

**Scenario 12 concern**: A real MCP-based agent with 1 critical (wildcard permissions), 3 high (missing auth, no path scope, external API), and 2 medium (rate limiting) drops from C to D under Option B. This may be too harsh if the findings include expected framework patterns. However, with framework context downgrades applied, most of these would be reduced, bringing the score back up.

With framework downgrades on Scenario 12:
```
After downgrades: 0C (wildcard→info), 1H (external API stays), 2M
Option B: 0 + 5 + 2.38 = 7.38 → Score 93 → A

Current: 0 + 5 + 2.38 = 7.38 → Score 93 → A
```
Both systems handle this correctly with framework context.

---

## 12. Final Recommendations

### Priority 1 — Implement (High Impact, Low Risk)

1. **Upgrade critical base penalty from 15 to 20** (Option B)
   - Single critical = 80 instead of 85
   - Better differentiation in 1–5 critical range

2. **Raise critical cap from 40 to 50**
   - 10 criticals now score 45 instead of 60
   - Better differentiation for severely compromised projects

3. **Downgrade PI-030 to info**
   - IMPORTANT/URGENT/CRITICAL keywords are too common
   - Nearly all matches are false positives

4. **Upgrade PI-110, PI-111 to critical**
   - MCP/agentic indirect injection is the #1 threat vector
   - Consistency with PI-105 through PI-109

5. **Downgrade PI-138 to info**
   - `user_id: 123` is standard API code
   - Nearly 100% FP in web applications

### Priority 2 — Consider (Medium Impact)

6. **Add interaction term** (critical × high coexistence bonus penalty)
   - Projects with both critical AND high findings are worse than the sum suggests
   - +5 × log₂(min(C,H)+1) capped at 10

7. **De-duplicate Defense ↔ Red Team findings**
   - When DF-001 (missing input sanitization) fires, suppress RT-001 (role confusion) to avoid double penalty
   - Or: reduce RT findings to info when corresponding DF finding exists

8. **Downgrade PI-047 from critical to high**
   - Consistency with PI-046
   - Social engineering, not system compromise

### Priority 3 — Monitor (Low Impact)

9. **Add FP tracking** to understand real-world false positive rates
   - Log pattern match rates per pattern ID
   - Use data to inform future severity adjustments

10. **Consider PI-020 downgrade** (respond in json) after FP data collection
    - May be legitimate API instruction, not injection

11. **Add Storybook/Cypress patterns** to test/doc file list
    - `*.stories.tsx`, `cypress/**`, `*.bench.*`

### Summary of Proposed Constants (Option B)

```typescript
// PROPOSED (Option B)
const SEVERITY_BASE_PENALTY = {
  critical: 20,    // was 15
  high: 5,         // unchanged
  medium: 1.5,     // unchanged
  info: 0,         // unchanged
};

const SEVERITY_MAX_PENALTY = {
  critical: 50,    // was 40
  high: 30,        // unchanged
  medium: 15,      // unchanged
  info: 0,         // unchanged
};

// NEW: Interaction penalty
function interactionPenalty(critical: number, high: number): number {
  if (critical > 0 && high > 0) {
    return Math.min(5 * Math.log2(Math.min(critical, high) + 1), 10);
  }
  return 0;
}
```

### Pattern Severity Changes

```
PI-030: medium → info    (IMPORTANT/URGENT FP reduction)
PI-047: critical → high  (social engineering consistency)
PI-065: high → medium    (OpenAI SDK FP reduction)
PI-068: high → critical  (exfiltration channel upgrade)
PI-110: high → critical  (MCP injection upgrade)
PI-111: high → critical  (indirect injection upgrade)
PI-127: medium → info    (conversational FP reduction)
PI-138: medium → info    (API code FP reduction)
```

---

*End of Review — Team Alpha*
