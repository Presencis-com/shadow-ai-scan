import { createHash, generateKeyPairSync, sign } from 'node:crypto';
export const formats = ['table', 'json', 'ai-bom', 'markdown'];
export const thresholds = ['high', 'elevated', 'any', 'none'];
const footer = 'Static scan covers local code and configuration. For live visibility across laptops, ' +
    'browsers, containers and cloud egress without prompt capture, see https://presencis.com/solutions/vigil/.';
const summaryLimit = 900_000;
const labels = ['Provider ID', 'Provider', 'Category', 'Risk', 'EU residency option', 'Hostname', 'File', 'Line', 'Reference'];
export function gate(findings, threshold) {
    return findings.some(({ riskTier }) => threshold === 'any' || (threshold === 'elevated' && riskTier !== 'standard') ||
        (threshold === 'high' && riskTier === 'high'));
}
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
function aiBom(findings) {
    const observed = new Date().toISOString();
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const document = {
        schema: 'presencis-ai-bom-v1',
        model: {
            name: 'Unidentified AI models',
            provenance: { origin: 'Local source and configuration scan', supplier: 'Unknown', retrieved_at: observed },
            base_architecture: 'Unknown',
            domain_specialization: { domain: 'Unknown', lineage: ['Unknown'] },
            precision: { quantization: 'Unknown', profile: 'Unknown' },
            evaluation: {
                state: 'untested',
                evidence_id: 'sha256:' + sha256(JSON.stringify(findings)),
                observed_at: observed,
                scope: 'Static hostname references: ' + findings.length + ' findings. See the JSON report for locations.',
                method: 'Hostname inventory; export signing key SPKI ' + spki.toString('base64'),
                limitations: 'Service references alone do not establish model use, model properties, compliance, ' +
                    'or supplier identity. Export key is created for this report and does not establish signer trust.',
            },
        },
        alignment: ['eu-ai-act-art-11'],
    };
    const payload = Buffer.from(JSON.stringify(document));
    const attestation = {
        digest_alg: 'sha-256',
        digest_hex: sha256(payload),
        signature_alg: 'ed25519',
        signature_hex: sign(null, payload, privateKey).toString('hex'),
        key_id: sha256(spki),
    };
    return JSON.stringify({ ...document, model: { ...document.model, attestation } }, null, 2) + '\n';
}
function fields(finding) {
    return [
        finding.providerId, finding.providerName, finding.category, finding.riskTier,
        finding.euDataResidencyOption ? 'Yes' : 'No', finding.matchedPattern, finding.file,
        String(finding.line), finding.referenceUrl,
    ];
}
function escapeMarkdown(value) {
    return value.replace(/[&<>|[\]\\\x60!*_@#~]/g, char => '&#' + char.charCodeAt(0) + ';');
}
function markdownRow(cells) {
    return '| ' + cells.map(escapeMarkdown).join(' | ') + ' |\n';
}
export function markdown(findings, limit = Infinity) {
    const heading = '## Shadow AI scan\n\n' + findings.length + ' findings.\n\n';
    if (findings.length === 0)
        return heading + footer + '\n';
    const header = heading + markdownRow(labels) + markdownRow(labels.map(() => '---'));
    let size = Buffer.byteLength(header + footer) + 100;
    const rows = [];
    for (const finding of findings) {
        const row = markdownRow(fields(finding));
        size += Buffer.byteLength(row);
        if (size > limit)
            break;
        rows.push(row);
    }
    const note = rows.length < findings.length ? '\nShowing ' + rows.length + ' findings in this summary.\n' : '';
    return header + rows.join('') + note + '\n' + footer + '\n';
}
export function formatReport(findings, format) {
    switch (format) {
        case 'json': return JSON.stringify(findings, null, 2) + '\n';
        case 'ai-bom': return aiBom(findings);
        case 'markdown': return markdown(findings);
        case 'table': {
            const rows = findings.length ? [labels, ...findings.map(fields)] : [['No findings.']];
            return rows.map(row => row.join('\t')).join('\n') + '\n\n' + footer + '\n';
        }
    }
}
export function actionSummary(findings) {
    return markdown(findings, summaryLimit);
}
