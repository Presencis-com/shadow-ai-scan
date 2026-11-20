import { readFileSync, writeFileSync } from 'node:fs';

const [input] = process.argv.slice(2);
if (!input || process.argv.length !== 3) {
  console.error('Usage: node scripts/sync-taxonomy.mjs <public-endpoints.json>');
  process.exit(2);
}

const source = JSON.parse(readFileSync(input, 'utf8'));
const fields = {
  providerId: 'provider_id',
  providerName: 'provider_name',
  category: 'category',
  riskTier: 'compliance_risk_tier',
  euDataResidencyOption: 'eu_data_residency_option',
  matchedPattern: 'hostname_pattern',
  referenceUrl: 'reference_url',
};
const patterns = new Set();
const allowedRisk = new Set(['standard', 'elevated', 'high']);
const allowedHost = /^(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*$|^localhost:[1-9][0-9]{0,4}$/;
if (!Array.isArray(source) || source.length !== 54) throw new Error('Expected 54 public endpoints');
const taxonomy = source.map((row, index) => {
  const endpoint = Object.fromEntries(Object.entries(fields).map(([name, key]) => [name, row[key]]));
  const { matchedPattern, riskTier, euDataResidencyOption, referenceUrl } = endpoint;
  const link = URL.canParse(referenceUrl) ? new URL(referenceUrl) : null;
  if (!Object.entries(endpoint).every(([name, value]) => name === 'euDataResidencyOption' ?
    typeof value === 'boolean' : typeof value === 'string' && value.trim().length > 0 && !/[\p{C}]/u.test(value)) ||
    !allowedHost.test(matchedPattern) || patterns.has(matchedPattern) || !allowedRisk.has(riskTier) ||
    (matchedPattern.startsWith('localhost:') && Number(matchedPattern.split(':')[1]) > 65535) ||
    typeof euDataResidencyOption !== 'boolean' || !link || link.protocol !== 'https:' ||
    link.username || link.password) {
    throw new Error('Invalid public endpoint at row ' + (index + 1));
  }
  patterns.add(matchedPattern);
  return endpoint;
});
writeFileSync(new URL('../data/endpoints.json', import.meta.url), JSON.stringify(taxonomy, null, 2) + '\n');
