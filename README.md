# Shadow AI Scan

Find references to public AI services in local code and configuration. Runs on Linux with Node.js 22 or newer. The scanner uses Linux file descriptors to keep reads inside the chosen directory.

```sh
npx @presencis/shadow-ai-scan .
npx @presencis/shadow-ai-scan ./services --format json --fail-on elevated
npx @presencis/shadow-ai-scan . --format ai-bom --out ai-bom.json
```

`--format` accepts `table` (default), `json`, `markdown`, and `ai-bom`. `--out` writes to a new file. An existing destination is preserved.

`--fail-on high` gates high findings, `elevated` gates elevated and high findings, `any` gates every finding, and `none` (default) disables the gate. Exit codes are 0 for a completed scan below the threshold, 1 for a completed scan that reaches the threshold, and 2 for invalid arguments or scan and output errors. A finding appears once per hostname pattern per file line.

The scanner skips symlinks, `.git`, `node_modules`, `dist`, binary or invalid UTF-8 files, and files over 2 MiB. Reports include repository-relative filenames and line numbers. The scanner never copies source line text into the report. Runtime code uses the Node standard library and makes no network requests.

The AI-BOM follows the public Presencis AI-BOM schema. It describes unidentified model properties and records a SHA-256 digest of the compact JSON findings array. The Ed25519 key is generated per export. To verify export integrity, decode the SPKI public key in the method field, remove the attestation, and verify over the UTF-8 bytes of `JSON.stringify` applied to that document. The export key carries no external trust. The JSON inventory is the format for individual findings.

## GitHub Action

Use a Linux runner with Node.js 22 or newer and check out the repository before calling the action.

```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
- uses: actions/setup-node@v4
  with:
    node-version: '22'
- uses: Presencis-com/shadow-ai-scan@main
  id: shadow-ai
  with:
    target: '.'
    fail-on: high
```

The action writes a Markdown step summary and sets `findings-count`, `high-risk-count`, and `ai-bom-path`. Read the BOM path from the same job. To consume it after a failed gate, give the consuming step a condition that runs on failure.

## Develop

Run `npm ci` and `unshare -c -p -f --mount-proc npm test` on Linux. The TypeScript build writes `dist/`, which the CLI and Action both run.

`node scripts/sync-taxonomy.mjs /path/to/endpoints.json` refreshes the 54-host inventory from the public Apache-2.0 Presencis endpoint taxonomy. The inventory includes only metadata used in findings. The test schema is a verbatim copy from the public Presencis BOM schemas.

Static scan covers local code and configuration. For live visibility across laptops, browsers, containers and cloud egress without prompt capture, see [Vigil](https://presencis.com/solutions/vigil/).
