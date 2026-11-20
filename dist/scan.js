import { closeSync, constants, fstatSync, openSync, readdirSync, readFileSync, readSync, realpathSync, } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';
const endpoints = JSON.parse(readFileSync(new URL('../data/endpoints.json', import.meta.url), 'utf8'));
const byPattern = new Map(endpoints.map(endpoint => [endpoint.matchedPattern, endpoint]));
const excluded = new Set(['.git', 'node_modules', 'dist']);
const maxBytes = 2 * 1024 * 1024;
const dirFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const fileFlags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const skippedEntryErrors = new Set(['ENOENT', 'ENOTDIR', 'ELOOP']);
const utf8 = new TextDecoder('utf-8', { fatal: true });
function contains(root, target) {
    const rel = relative(root, target);
    return !isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + sep);
}
function fdPath(fd) {
    return '/proc/self/fd/' + fd;
}
function readText(fd) {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes)
        return;
    const bytes = Buffer.allocUnsafe(Math.min(stat.size + 1, maxBytes + 1));
    let offset = 0;
    while (offset < bytes.length) {
        const count = readSync(fd, bytes, offset, bytes.length - offset, null);
        if (count === 0)
            break;
        offset += count;
    }
    if (offset > stat.size)
        return;
    const body = bytes.subarray(0, offset);
    try {
        const text = utf8.decode(body);
        if (/[\u0000-\u0008\u000b\u000e-\u001f\u007f]/.test(text))
            return;
        return text;
    }
    catch {
        return;
    }
}
function endpointPattern(value) {
    const [host, port] = value.toLowerCase().replace(/\.(?=:|$)/, '').split(':');
    if (host === 'localhost')
        return host + ':' + port;
    if (host.endsWith('.openai.azure.com'))
        return 'openai.azure.com';
    if (host.endsWith('.snowflakecomputing.com'))
        return 'snowflakecomputing.com';
    if (/^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/.test(host))
        return 'bedrock-runtime.amazonaws.com';
    return host;
}
function displayPath(file) {
    return file.replace(/[\p{C}\u2028\u2029]/gu, character => '\\u{' + character.codePointAt(0).toString(16) + '}');
}
function findInText(text, file, findings) {
    const lines = text.split(/\r\n|\n|\r/);
    for (const [index, line] of lines.entries()) {
        const patterns = new Set();
        for (const match of line.matchAll(/localhost:[a-z0-9_.-]+|[a-z0-9_.-]+/gi)) {
            const pattern = endpointPattern(match[0]);
            if (byPattern.has(pattern))
                patterns.add(pattern);
        }
        for (const pattern of [...patterns].sort()) {
            findings.push({ ...byPattern.get(pattern), file: displayPath(file), line: index + 1 });
        }
    }
}
export function scan(target, workspace) {
    const root = realpathSync(target);
    if (workspace !== undefined && !contains(realpathSync(workspace), root)) {
        throw new Error('Scan target must be in the workspace');
    }
    const findings = [];
    function visit(fd, path) {
        const entries = readdirSync(fdPath(fd), { withFileTypes: true });
        entries.sort((a, b) => a.name < b.name ? -1 : Number(a.name > b.name));
        for (const entry of entries) {
            if (excluded.has(entry.name) || (!entry.isDirectory() && !entry.isFile()))
                continue;
            const rel = join(path, entry.name);
            // Resolve each child relative to its opened parent and refuse final symlinks.
            let child;
            try {
                child = openSync(join(fdPath(fd), entry.name), entry.isDirectory() ? dirFlags : fileFlags);
            }
            catch (error) {
                if (skippedEntryErrors.has(error.code ?? ''))
                    continue;
                throw error;
            }
            try {
                if (!contains(root, realpathSync(fdPath(child))))
                    continue;
                if (entry.isDirectory()) {
                    visit(child, rel);
                }
                else {
                    const text = readText(child);
                    if (text !== undefined)
                        findInText(text, rel, findings);
                }
            }
            finally {
                closeSync(child);
            }
        }
    }
    const fd = openSync(root, dirFlags);
    try {
        if (realpathSync(fdPath(fd)) !== root)
            throw new Error('Scan root changed');
        visit(fd, '');
    }
    finally {
        closeSync(fd);
    }
    return findings;
}
