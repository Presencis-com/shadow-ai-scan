import { appendFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { actionSummary, formatReport, gate, thresholds } from './report.js';
import { scan } from './scan.js';
function environment(name) {
    const value = process.env[name];
    if (!value || /[\r\n]/.test(value))
        throw new Error('Invalid action environment');
    return value;
}
try {
    const workspace = environment('GITHUB_WORKSPACE');
    const target = resolve(workspace, environment('SCAN_TARGET'));
    const summary = environment('GITHUB_STEP_SUMMARY');
    const outputs = environment('GITHUB_OUTPUT');
    const temporary = environment('RUNNER_TEMP');
    const threshold = thresholds.find(value => value === environment('SCAN_FAIL_ON'));
    if (!threshold)
        throw new Error('Invalid gate threshold');
    const findings = scan(target, workspace);
    const high = findings.filter(row => row.riskTier === 'high').length;
    const bom = join(mkdtempSync(join(temporary, 'shadow-ai-scan-')), 'ai-bom.json');
    writeFileSync(bom, formatReport(findings, 'ai-bom'), { flag: 'wx', mode: 0o600 });
    appendFileSync(summary, actionSummary(findings));
    appendFileSync(outputs, 'findings-count=' + findings.length + '\nhigh-risk-count=' + high +
        '\nai-bom-path=' + bom + '\n');
    process.exitCode = gate(findings, threshold) ? 1 : 0;
}
catch {
    process.stderr.write('shadow-ai-scan: action inputs, scan or report output failed.\n');
    process.exitCode = 2;
}
