import { stripAnsi } from './util.js';

// JumpServer prints a pipe table whose header is localized:
//   ID | name | address | protocol | platform | org | note
//   1  | foo  | 10.0.0.1 | ssh | Linux | Default | test box
// Columns are read positionally because the words in the header change with the
// UI language, while their order does not.
export function parseAssetList(rawText) {
    const text = stripAnsi(rawText);
    const assets = [];
    for (const line of text.split(/\r?\n/)) {
        if (!line.includes('|')) {
            const loose = line.match(/^\s*(\d{1,6})\s{2,}(\S.*?)\s*$/);
            if (loose) {
                const rest = loose[2].trim();
                assets.push({
                    id: Number(loose[1]),
                    name: rest.split(/\s{2,}/)[0],
                    ip: (rest.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || [])[0] || null,
                    raw: rest,
                });
            }
            continue;
        }
        if (/^-+(\+-+)+$/.test(line.replace(/\s/g, ''))) continue;
        const cells = line.split('|').map(cell => cell.trim());
        const id = Number(cells[0]);
        if (!Number.isInteger(id) || cells.length < 3) continue;
        const [, name, address, protocol, platform, org, ...tail] = cells;
        assets.push({
            id,
            name,
            ip: address || null,
            protocol: protocol || null,
            platform: platform || null,
            org: org || null,
            note: tail.join(' | ').trim() || null,
        });
    }
    return assets;
}

export function parsePageInfo(rawText) {
    const text = stripAnsi(rawText);
    // The page footer is localized too, so both spellings are matched by the
    // characters the bastion actually prints.
    const zh = text.match(/\u603B\u9875\u6570[\uFF1A:]\s*(\d+)[^\d]*\u603B\u6570\u91CF[\uFF1A:]\s*(\d+)/);
    if (zh) return { pages: Number(zh[1]), total: Number(zh[2]) };
    const en = text.match(/page[^\d]{0,12}(\d+)\s*\/\s*(\d+)/i);
    if (en) return { pages: Number(en[2]), total: null };
    return { pages: 1, total: null };
}
