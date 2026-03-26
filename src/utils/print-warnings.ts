import chalk from 'chalk';

/**
 * Print non-fatal config warnings to stderr.
 * Outputs one line per warning followed by a blank separator line.
 * Called from cli.ts when sentoriConfig.warnings.length > 0.
 */
export function printConfigWarnings(warnings: string[]): void {
  for (const w of warnings) {
    console.warn(chalk.yellow(`  ⚠ ${w}`));
  }
  console.warn('');
}
