// Public, keyless threat feeds refreshed automatically (cached per server instance).
const FEEDS = [
  { name: "OpenPhish", url: "https://openphish.com/feed.txt", kind: "phishing" },
  { name: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/text_recent/", kind: "malware" },
] as const;

const TTL_MS = 30 * 60 * 1000;
// Shared hosting where a single bad URL must not flag the whole domain.
const SHARED_HOSTS = /(^|\.)(github\.com|githubusercontent\.com|google\.com|googleapis\.com|r2\.dev|dropbox\.com|drive\.google\.com|discord(app)?\.com|cdn\.discordapp\.com|microsoft\.com|onedrive\.live\.com|amazonaws\.com|pages\.dev|workers\.dev|vercel\.app|netlify\.app|blogspot\.com|wordpress\.com|weebly\.com|wixsite\.com|firebaseapp\.com|web\.app|telegra\.ph)$/i;

type Entry = { source: string; kind: string };
type Db = { urls: Map<string, Entry>; hosts: Map<string, Entry>; updatedAt: number; total: number };

let db: Db | null = null;
let loading: Promise<Db> | null = null;

const norm = (u: string) => u.trim().toLowerCase().replace(/\/+$/, "");

async function load(): Promise<Db> {
  const urls = new Map<string, Entry>();
  const hosts = new Map<string, Entry>();
  await Promise.all(
    FEEDS.map(async (f) => {
      try {
        const res = await fetch(f.url, { headers: { "User-Agent": "Sentinel/1.0" } });
        if (!res.ok) return;
        for (const line of (await res.text()).split("\n")) {
          const l = line.trim();
          if (!l || l.startsWith("#")) continue;
          const e = { source: f.name, kind: f.kind };
          urls.set(norm(l), e);
          try {
            const h = new URL(l).hostname.toLowerCase();
            if (!SHARED_HOSTS.test(h)) hosts.set(h, e);
          } catch {}
        }
      } catch {}
    }),
  );
  return { urls, hosts, updatedAt: Date.now(), total: urls.size };
}

export async function getThreatDb(): Promise<Db> {
  if (db && Date.now() - db.updatedAt < TTL_MS) return db;
  loading ??= load().then((d) => {
    if (d.total > 0 || !db) db = d;
    loading = null;
    return db!;
  });
  return db ?? loading;
}

export async function checkUrlsInText(text: string) {
  const found = text.match(/\bhttps?:\/\/[^\s<>"')]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"')]*)?/gi) ?? [];
  if (!found.length) return [];
  const d = await getThreatDb();
  return found.slice(0, 20).map((raw) => {
    const full = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    let host = "";
    try { host = new URL(full).hostname.toLowerCase(); } catch {}
    const hit = d.urls.get(norm(full)) ?? d.urls.get(norm(full.replace(/^http:/i, "https:"))) ?? (host ? d.hosts.get(host) : undefined);
    return { url: raw, listed: !!hit, source: hit?.source, kind: hit?.kind };
  });
}
