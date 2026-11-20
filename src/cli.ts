#!/usr/bin/env node
import { linkSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { formatReport, formats, gate, thresholds, type Format, type Threshold } from './report.js';
import { scan } from './scan.js';

const usage = 'Usage: shadow-ai-scan [targetDir] [--format table|json|ai-bom|markdown] ' +
  '[--fail-on high|elevated|any|none] [--out file]\n';

try {
  const { values, positionals, tokens } = parseArgs({
    allowPositionals: true,
    tokens: true,
    options: {
      format: { type: 'string', default: 'table' },
      'fail-on': { type: 'string', default: 'none' },
      out: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const optionNames = tokens.flatMap(token => token.kind === 'option' ? [token.name] : []);
  const format = formats.find(candidate => candidate === values.format);
  const threshold = thresholds.find(candidate => candidate === values['fail-on']);
  if (!format || !threshold || positionals.length > 1 || positionals[0] === '' ||
      values.out === '' || new Set(optionNames).size !== optionNames.length) {
    throw new Error('Invalid arguments');
  }
  if (values.help) {
    process.stdout.write(usage);
  } else {
    process.exitCode = run(positionals[0] ?? '.', format, threshold, values.out);
  }
} catch {
  process.stderr.write('shadow-ai-scan: invalid arguments or scan/output failed.\n' + usage);
  process.exitCode = 2;
}

function run(target: string, format: Format, threshold: Threshold, output?: string): number {
  const findings = scan(target);
  const report = formatReport(findings, format);
  if (output === undefined) process.stdout.write(report);
  else writeNewReport(output, report);
  return gate(findings, threshold) ? 1 : 0;
}

function writeNewReport(output: string, report: string): void {
  const staging = mkdtempSync(join(dirname(output), '.shadow-ai-scan-'));
  const file = join(staging, 'report');
  try {
    writeFileSync(file, report, { flag: 'wx', mode: 0o600 });
    linkSync(file, output);
  } finally {
    rmSync(staging, { recursive: true });
  }
}
