import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const action = fileURLToPath(new URL('../dist/action.js', import.meta.url));
const schema = JSON.parse(readFileSync(new URL('ai-bom.schema.json', import.meta.url)));
const validateBom = new Ajv2020({ allErrors: true }).compile(schema);
const fixtureValue = 'fixture-only-' + 'S3cr3t-never-in-output';

function fixture(t) {
  const base = mkdtempSync(join(tmpdir(), 'static-scan-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, 'repo');
  mkdirSync(root);
  return { base, root };
}

function run(script, args, options = {}) {
  const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', ...options });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}

test('output formats redact input text and expose only allowed finding fields', t => {
  const {root} = fixture(t);
  writeFileSync(join(root, 'input.env'), 'Authorization: Bearer ' + fixtureValue +
    '\nKEY=' + fixtureValue + ' URL=https://API.OPENAI.COM/v1?value=' + fixtureValue + '\n');
  for (const format of ['table', 'json', 'ai-bom', 'markdown']) {
    const { status, stdout, stderr } = run(cli, [root, '--format', format]);
    assert.equal(status, 0, stderr);
    assert.ok(![stdout, stderr].join('').includes(fixtureValue), 'fixture value leaked in ' + format);
    assert.ok(!stdout.includes('Authorization: Bearer'));
    if (format !== 'ai-bom') assert.match(stdout, /api\.openai\.com/);
    if (format === 'json') {
      assert.deepEqual(JSON.parse(stdout), [{
        providerId: 'openai-api', providerName: 'OpenAI', category: 'commercial-api',
        riskTier: 'elevated', euDataResidencyOption: true, matchedPattern: 'api.openai.com',
        file: 'input.env', line: 2, referenceUrl: 'https://platform.openai.com/docs',
      }]);
    }
  }
});

test('symlink escapes, excluded paths, invalid text and oversized files stay out', t => {
  const {base, root} = fixture(t);
  const outside = join(base, 'repo-other');
  mkdirSync(outside);
  writeFileSync(join(outside, 'outside.txt'), 'api.openai.com');
  symlinkSync(outside, join(root, 'directory-link'));
  symlinkSync(join(outside, 'outside.txt'), join(root, 'file-link.txt'));
  for (const name of ['.git', 'node_modules', 'dist']) {
    mkdirSync(join(root, name));
    writeFileSync(join(root, name, 'ignore.txt'), 'api.openai.com');
  }
  writeFileSync(join(root, 'binary.bin'), Buffer.from('\u0000api.openai.com'));
  writeFileSync(join(root, 'invalid.txt'), Buffer.concat([Buffer.from([0xff]), Buffer.from('api.openai.com')]));
  writeFileSync(join(root, 'big.txt'), 'api.openai.com' + ' '.repeat(2 * 1024 * 1024));
  const edge = 'api.openai.com'.padEnd(2 * 1024 * 1024, ' ');
  writeFileSync(join(root, 'edge.txt'), edge);
  const result = run(cli, [root, '--format', 'json']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout).map(finding => finding.file), ['edge.txt']);
});

test('patterns match host boundaries, regional subdomains and exact service ports', t => {
  const {root} = fixture(t);
  writeFileSync(join(root, 'urls.txt'), [
    'https://not-api.openai.com https://api.openai.com.evil.test http://localhost:12345',
    'https://tenant.openai.azure.com https://API.OPENAI.COM:443/v1 http://localhost:1234/',
    'api.openai.com and api.openai.com.\nHOST:api.openai.com',
  ].join('\r\n'));
  const result = run(cli, [root, '--format', 'json']);
  assert.equal(result.status, 0, result.stderr);
  const pairs = JSON.parse(result.stdout).map(row => [row.matchedPattern, row.line]);
  assert.deepEqual(pairs, [['api.openai.com', 2], ['localhost:1234', 2], ['openai.azure.com', 2], ['api.openai.com', 3], ['api.openai.com', 4]]);
});

test('AI-BOM validates against the public schema and binds only static findings', t => {
  const {root} = fixture(t);
  for (const body of ['', 'AI_URL=api.deepseek.com']) {
    writeFileSync(join(root, 'example.env'), body);
    const scan = run(cli, [root, '--format', 'json']);
    const result = run(cli, [root, '--format', 'ai-bom']);
    assert.equal(result.status, 0, result.stderr);
    const bom = JSON.parse(result.stdout);
    assert.equal(validateBom(bom), true, JSON.stringify(validateBom.errors));
    assert.equal(bom.model.evaluation.state, 'untested');
    const evidence = createHash('sha256').update(JSON.stringify(JSON.parse(scan.stdout))).digest('hex');
    assert.equal(bom.model.evaluation.evidence_id, 'sha256:' + evidence);
    const publicKey = Buffer.from(bom.model.evaluation.method.split(' SPKI ')[1], 'base64');
    const { attestation } = bom.model;
    delete bom.model.attestation;
    const payload = Buffer.from(JSON.stringify(bom));
    assert.equal(attestation.digest_hex, createHash('sha256').update(payload).digest('hex'));
    assert.equal(attestation.key_id, createHash('sha256').update(publicKey).digest('hex'));
    assert.ok(verify(null, payload, createPublicKey({ key: publicKey, type: 'spki', format: 'der' }),
      Buffer.from(attestation.signature_hex, 'hex')));
  }
});

test('all gate thresholds distinguish clean and matching files', t => {
  const {root} = fixture(t);
  for (const [body, expected] of [['', [0,0,0,0]], ['api.openai.com', [0,1,1,0]],
    ['api.deepseek.com', [1,1,1,0]], ['localhost:1234', [0,0,1,0]]]) {
    writeFileSync(join(root, 'input.txt'), body);
    for (const [index, threshold] of ['high', 'elevated', 'any', 'none'].entries()) {
      const result = run(cli, [root, '--format', 'json', '--fail-on', threshold]);
      assert.equal(result.status, expected[index], 'unexpected gate result at ' + threshold);
      assert.equal(result.stderr, '');
    }
  }
});

test('output file is written on gate failure and invalid flags fail with a safe message', t => {
  const {base, root} = fixture(t);
  const path = join(base, 'report.json');
  writeFileSync(join(root, 'input.txt'), 'api.deepseek.com');
  const result = run(cli, [root, '--out', path, '--format', 'json', '--fail-on', 'high']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  const original = readFileSync(path);
  assert.equal(JSON.parse(original)[0].riskTier, 'high');
  assert.equal(run(cli, [root, '--out', path]).status, 2);
  assert.deepEqual(readFileSync(path), original);
  for (const args of [['--format', fixtureValue], ['--fail-on', ''], ['--out'], [root, root], [join(base, fixtureValue)]]) {
    const invalid = run(cli, args);
    assert.equal(invalid.status, 2);
    assert.ok(!invalid.stderr.includes(fixtureValue));
  }
});

test('Markdown and terminal output treat a filename as plain text', t => {
  const {root} = fixture(t);
  writeFileSync(join(root, '<img>|name\n\u001b.txt'), 'api.openai.com');
  const markdown = run(cli, [root, '--format', 'markdown']).stdout;
  assert.match(markdown, /&#60;img&#62;&#124;name/);
  assert.ok(!markdown.includes('<img>'));
  assert.ok(!run(cli, [root]).stdout.includes('\u001b'));
});

test('action writes summary, BOM and outputs before applying a failed gate', t => {
  const {base, root} = fixture(t);
  writeFileSync(join(root, 'input.txt'), 'api.deepseek.com ' + fixtureValue);
  const summary = join(base, 'summary');
  const outputs = join(base, 'outputs');
  const result = run(action, [], {
    env: { ...process.env, GITHUB_WORKSPACE: root, RUNNER_TEMP: base,
      GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: outputs,
      SCAN_TARGET: '.', SCAN_FAIL_ON: 'high' },
  });
  assert.equal(result.status, 1, result.stderr);
  const markdown = readFileSync(summary, 'utf8');
  assert.match(markdown, /api\.deepseek\.com/);
  assert.match(markdown, /https:\/\/presencis\.com\/solutions\/vigil\//);
  assert.ok(!markdown.includes(fixtureValue));
  const outputsText = readFileSync(outputs, 'utf8');
  assert.match(outputsText, /^findings-count=1\nhigh-risk-count=1\nai-bom-path=/);
  const bomPath = outputsText.match(/^ai-bom-path=(.+)$/m)[1];
  assert.equal(validateBom(JSON.parse(readFileSync(bomPath))), true);
});

test('the action refuses a target outside the checkout and leaves outputs untouched', t => {
  const {base, root} = fixture(t);
  const summary = join(base, 'summary');
  const outputs = join(base, 'outputs');
  const result = run(action, [], {
    env: { ...process.env, GITHUB_WORKSPACE: root, RUNNER_TEMP: base,
      GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: outputs,
      SCAN_TARGET: '..', SCAN_FAIL_ON: 'none' },
  });
  assert.equal(result.status, 2);
  assert.throws(() => readFileSync(summary), { code: 'ENOENT' });
  assert.throws(() => readFileSync(outputs), { code: 'ENOENT' });
});
