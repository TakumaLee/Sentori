# .sentori.yml — Custom Configuration

Place `.sentori.yml` in the root of the directory you're scanning.

## Schema

```yaml
version: 1

# User-defined pattern rules (run as a new "Custom Rules" scanner)
rules:
  - id: no-hardcoded-aws-key
    pattern: "AKIA[0-9A-Z]{16}"
    severity: critical
    message: "Hardcoded AWS access key ID"
    files: "**/*.{ts,js,py}"  # optional glob — defaults to all files

  - id: no-internal-api-url
    pattern: "https://internal\\.corp\\.example\\.com"
    severity: high
    message: "Internal API URL exposed in source"

# Suppress findings — all specified fields must match (unspecified = wildcard)
ignore:
  - scanner: "Secret Leak Scanner"
    file: "tests/**"              # suppress from this scanner in test files only

  - rule: "PINJ-001"              # suppress a specific rule ID across all scanners

  - file: "demo-vulnerable-agent/**"  # suppress all findings in this directory

  - scanner: "Red Team Simulator"     # suppress all findings from a scanner

# Override severity of built-in findings
overrides:
  - scanner: "Prompt Injection Tester"
    severity: medium              # downgrade all findings from this scanner

  - scanner: "Supply Chain Scanner"
    rule: "BASE64_HIDDEN_CMD"
    severity: critical            # promote a specific rule
```

## Fields

### `rules[]`
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique rule ID (appears in report as `rule` field) |
| `pattern` | string | yes | ECMAScript regex pattern |
| `severity` | `critical\|high\|medium\|info` | yes | Finding severity |
| `message` | string | yes | Human-readable finding description |
| `files` | glob string | no | Restrict to matching files (default: all files) |

### `ignore[]`
Each entry suppresses findings where **all specified fields match**:

| Field | Type | Description |
|-------|------|-------------|
| `scanner` | string | Scanner name (e.g. `"Secret Leak Scanner"`) |
| `rule` | string | Rule/finding ID |
| `file` | glob string | File path (relative to scan target) |

### `overrides[]`
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scanner` | string | yes | Scanner name to apply override to |
| `rule` | string | no | Restrict to specific rule ID |
| `severity` | `critical\|high\|medium\|info` | yes | Target severity |

## ReDoS Warning

Custom rule patterns are compiled as ECMAScript regex and executed against each line of scanned files.
**Avoid patterns that can cause catastrophic backtracking**, which may hang the scanner indefinitely:

| Dangerous pattern | Why |
|---|---|
| `(a+)+`, `(\w+)*` | Nested quantifiers — exponential backtracking |
| `(foo\|foobar)+` | Alternation where branches overlap + outer quantifier |
| `(a*)*` | Redundant quantifier nesting |

Sentori emits a **warning** (not an error) when it detects these patterns heuristically, but the
heuristic is not exhaustive. Always test your patterns on representative inputs before deploying to CI.

**Safe alternatives:**
- Use possessive quantifiers where possible (e.g. `[A-Z0-9]{16}` instead of `([A-Z0-9]+)+`)
- Anchor patterns to avoid unnecessary backtracking (e.g. `^` / `$` / `\b`)
- Test with [regex101.com](https://regex101.com) using the "Catastrophic Backtracking" debugger
