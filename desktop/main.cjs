const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, shell, dialog } = require("electron");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { execFile } = require("child_process");

const isWin = process.platform === "win32";
let win = null;
let tray = null;

/* ---------------- shell helpers ---------------- */

function run(cmd, args, timeout = 20000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) =>
      resolve({ ok: !err, out: stdout || "", err: (stderr || "") + (err ? String(err.message) : "") }),
    );
  });
}

function ps(script) {
  return run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]);
}

// Runs a command elevated (UAC prompt) — needed for firewall rules and killing protected processes.
function psElevated(inner) {
  const encoded = Buffer.from(inner, "utf16le").toString("base64");
  return ps(`Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile','-EncodedCommand','${encoded}'`);
}

function jsonFromPs(out) {
  const t = out.trim();
  if (!t) return [];
  try {
    const v = JSON.parse(t);
    return Array.isArray(v) ? v : [v];
  } catch {
    return [];
  }
}

/* ---------------- threat feeds ---------------- */

const FEEDS = [
  { name: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/text_recent/", kind: "malware" },
  { name: "OpenPhish", url: "https://openphish.com/feed.txt", kind: "phishing" },
];
const feed = { hosts: new Map(), ips: new Set(), total: 0, updatedAt: 0 };

async function refreshFeeds() {
  const hosts = new Map();
  const ips = new Set();
  let total = 0;
  for (const f of FEEDS) {
    try {
      const res = await fetch(f.url, { headers: { "User-Agent": "Sentinel-Desktop/1.0" } });
      if (!res.ok) continue;
      for (const line of (await res.text()).split("\n")) {
        const l = line.trim();
        if (!l || l.startsWith("#")) continue;
        total++;
        try {
          const h = new URL(l).hostname.toLowerCase();
          if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) ips.add(h);
          else hosts.set(h, f.name);
        } catch {}
      }
    } catch {}
  }
  if (total > 0) {
    feed.hosts = hosts;
    feed.ips = ips;
    feed.total = total;
    feed.updatedAt = Date.now();
  }
  return { total: feed.total, updatedAt: feed.updatedAt };
}

/* ---------------- scanning ---------------- */

const SYSTEM_DIRS = [/\\windows\\system32\\/i, /\\windows\\syswow64\\/i, /\\program files/i];
const SUSPECT_DIRS = [/\\appdata\\local\\temp\\/i, /\\appdata\\roaming\\/i, /\\downloads\\/i, /\\users\\public\\/i, /\\programdata\\/i];
const RISKY_EXT = /\.(exe|scr|bat|cmd|ps1|vbs|js|jar|msi|hta|lnk|dll|pif|com|reg)$/i;
const LIVING_OFF_LAND = /\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|schtasks)\.exe$/i;

function judgeProcess(p) {
  const reasons = [];
  let score = 0;
  const pth = p.path || "";
  if (!pth) {
    reasons.push("Percorso non leggibile (processo protetto o di sistema)");
  } else {
    if (SUSPECT_DIRS.some((r) => r.test(pth))) {
      score += 2;
      reasons.push("Si avvia da una cartella temporanea o di download");
    }
    if (!p.company) {
      score += 1;
      reasons.push("Nessun editore dichiarato");
    }
    if (p.signature && p.signature !== "Valid") {
      score += 2;
      reasons.push("Firma digitale assente o non valida");
    }
    if (LIVING_OFF_LAND.test(pth) && SUSPECT_DIRS.some((r) => r.test(p.cmd || ""))) {
      score += 2;
      reasons.push("Strumento di sistema usato su file in cartelle sospette");
    }
    if (/\\windows\\/i.test(pth) && !SYSTEM_DIRS.some((r) => r.test(pth))) {
      score += 2;
      reasons.push("Si trova nella cartella Windows ma fuori dalle posizioni di sistema");
    }
  }
  if (p.cpu > 60) {
    score += 1;
    reasons.push("Uso della CPU molto alto");
  }
  return { level: score >= 3 ? "danger" : score >= 1 ? "warn" : "safe", reasons };
}

async function scanProcesses() {
  if (!isWin) return [];
  const script = `
$ErrorActionPreference='SilentlyContinue'
Get-Process | Where-Object { $_.Id -gt 4 } | ForEach-Object {
  $p=$_; $sig=$null
  if ($p.Path) { $sig = (Get-AuthenticodeSignature -FilePath $p.Path).Status.ToString() }
  [PSCustomObject]@{
    pid=$p.Id; name=$p.ProcessName; path=$p.Path
    company=$p.Company; cpu=[math]::Round($p.CPU,1)
    mem=[math]::Round($p.WorkingSet64/1MB,1); signature=$sig
  }
} | Sort-Object -Property mem -Descending | Select-Object -First 80 | ConvertTo-Json -Compress`;
  const { out } = await ps(script);
  return jsonFromPs(out).map((p) => ({ ...p, judgement: judgeProcess(p) }));
}

const SAFE_PORTS = new Set([80, 443, 53, 123, 993, 587, 22]);
const RISKY_PORTS = new Map([
  [3389, "Desktop remoto esposto"],
  [445, "Condivisione file Windows"],
  [23, "Telnet, protocollo non cifrato"],
  [21, "FTP, protocollo non cifrato"],
  [5900, "VNC, controllo remoto"],
  [4444, "Porta usata spesso da malware"],
  [1337, "Porta usata spesso da malware"],
  [6667, "IRC, usato da botnet"],
]);

function isPrivate(ip) {
  return /^(10\.|127\.|0\.0\.0\.0|::|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1)/.test(ip);
}

async function scanConnections() {
  if (!isWin) return [];
  const script = `
$ErrorActionPreference='SilentlyContinue'
$procs=@{}; Get-Process | ForEach-Object { $procs[$_.Id]=$_.ProcessName }
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' } | ForEach-Object {
  [PSCustomObject]@{
    local=$_.LocalAddress; lport=$_.LocalPort; remote=$_.RemoteAddress; rport=$_.RemotePort
    state=$_.State.ToString(); pid=$_.OwningProcess; name=$procs[[int]$_.OwningProcess]
  }
} | Select-Object -First 120 | ConvertTo-Json -Compress`;
  const { out } = await ps(script);
  return jsonFromPs(out).map((c) => {
    const reasons = [];
    let level = "safe";
    const listening = c.state === "Listen";
    if (feed.ips.has(String(c.remote))) {
      level = "danger";
      reasons.push("L'indirizzo remoto è nell'elenco URLhaus delle minacce");
    }
    if (listening && RISKY_PORTS.has(c.lport) && !isPrivate(c.local)) {
      level = level === "danger" ? level : "danger";
      reasons.push(`Porta ${c.lport} aperta verso l'esterno: ${RISKY_PORTS.get(c.lport)}`);
    } else if (listening && RISKY_PORTS.has(c.lport)) {
      if (level !== "danger") level = "warn";
      reasons.push(`Porta ${c.lport} in ascolto: ${RISKY_PORTS.get(c.lport)}`);
    }
    if (!listening && !isPrivate(String(c.remote)) && !SAFE_PORTS.has(c.rport) && c.rport > 1024) {
      if (level === "safe") level = "warn";
      reasons.push(`Collegamento verso una porta insolita (${c.rport})`);
    }
    return { ...c, judgement: { level, reasons } };
  });
}

async function scanFiles() {
  if (!isWin) return [];
  const home = os.homedir();
  const dirs = [path.join(home, "Downloads"), path.join(home, "Desktop"), path.join(os.tmpdir())];
  const items = [];
  for (const dir of dirs) {
    let names = [];
    try {
      names = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const n of names) {
      const full = path.join(dir, n);
      let st;
      try {
        st = fs.statSync(full);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      if (Date.now() - st.mtimeMs > 7 * 24 * 3600 * 1000) continue;
      items.push({ name: n, path: full, dir, size: st.size, mtime: st.mtimeMs });
    }
  }
  items.sort((a, b) => b.mtime - a.mtime);
  const top = items.slice(0, 60);
  for (const f of top) {
    const reasons = [];
    let level = "safe";
    if (RISKY_EXT.test(f.name)) {
      level = "warn";
      reasons.push("File eseguibile: può avviare programmi");
    }
    if (/\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\.(exe|scr|js|bat|cmd|vbs)$/i.test(f.name)) {
      level = "danger";
      reasons.push("Doppia estensione: finge di essere un documento");
    }
    if (/[\u202e\u200f]/.test(f.name)) {
      level = "danger";
      reasons.push("Nome del file con caratteri nascosti che invertono l'estensione");
    }
    if (RISKY_EXT.test(f.name) && /\\temp\\/i.test(f.dir)) {
      level = "danger";
      reasons.push("Eseguibile nella cartella temporanea");
    }
    if (level !== "safe" && RISKY_EXT.test(f.name)) {
      const { out } = await ps(`(Get-AuthenticodeSignature -FilePath '${f.path.replace(/'/g, "''")}').Status.ToString()`);
      const sig = out.trim();
      f.signature = sig;
      if (sig && sig !== "Valid") reasons.push("Firma digitale assente o non valida");
      else if (sig === "Valid" && level === "warn") {
        level = "safe";
        reasons.length = 0;
        reasons.push("Firmato da un editore riconosciuto");
      }
    }
    f.judgement = { level, reasons };
  }
  return top;
}

/* ---------------- actions ---------------- */

async function killProcess(pid, name) {
  let r = await ps(`Stop-Process -Id ${Number(pid)} -Force -ErrorAction Stop`);
  if (!r.ok) r = await psElevated(`Stop-Process -Id ${Number(pid)} -Force`);
  return { ok: r.ok, message: r.ok ? `Processo ${name} chiuso.` : `Non sono riuscito a chiudere ${name}. Potrebbe essere protetto dal sistema.` };
}

async function blockIp(ip) {
  if (!/^[0-9a-f.:]+$/i.test(String(ip))) return { ok: false, message: "Indirizzo non valido." };
  const rule = `Sentinel blocco ${ip}`;
  const r = await psElevated(
    `New-NetFirewallRule -DisplayName '${rule}' -Direction Outbound -RemoteAddress ${ip} -Action Block -Profile Any; ` +
      `New-NetFirewallRule -DisplayName '${rule} (in)' -Direction Inbound -RemoteAddress ${ip} -Action Block -Profile Any`,
  );
  return { ok: r.ok, message: r.ok ? `Collegamenti con ${ip} bloccati nel firewall di Windows.` : "Blocco non riuscito: servono i permessi di amministratore." };
}

async function blockProgram(exePath, name) {
  if (!exePath) return { ok: false, message: "Percorso del programma sconosciuto." };
  const safe = exePath.replace(/'/g, "''");
  const r = await psElevated(
    `New-NetFirewallRule -DisplayName 'Sentinel blocco ${name}' -Direction Outbound -Program '${safe}' -Action Block -Profile Any`,
  );
  return { ok: r.ok, message: r.ok ? `${name} non può più collegarsi a internet.` : "Blocco non riuscito: servono i permessi di amministratore." };
}

async function quarantineFile(filePath) {
  const qdir = path.join(app.getPath("userData"), "quarantena");
  try {
    fs.mkdirSync(qdir, { recursive: true });
    const dest = path.join(qdir, `${Date.now()}_${path.basename(filePath)}.bloccato`);
    fs.renameSync(filePath, dest);
    await ps(`icacls '${dest.replace(/'/g, "''")}' /inheritance:r /deny '*S-1-1-0:(RX,X)'`);
    return { ok: true, message: `File messo in quarantena. Copia bloccata in ${qdir}.`, dest };
  } catch (e) {
    return { ok: false, message: `Quarantena non riuscita: ${e.message}` };
  }
}

async function defenderScan(target) {
  const r = await psElevated(
    target
      ? `Start-MpScan -ScanType CustomScan -ScanPath '${String(target).replace(/'/g, "''")}'`
      : `Start-MpScan -ScanType QuickScan`,
  );
  return { ok: r.ok, message: r.ok ? "Scansione di Windows Defender avviata." : "Non sono riuscito ad avviare la scansione." };
}

/* ---------------- alerts ---------------- */

let lastAlertKey = "";
function alertThreat(title, body) {
  const key = title + body;
  if (key === lastAlertKey) return;
  lastAlertKey = key;
  if (!Notification.isSupported()) return;
  const n = new Notification({ title, body, icon: path.join(__dirname, "icon.png"), urgency: "critical", timeoutType: "never" });
  n.on("click", () => {
    if (win) {
      win.show();
      win.focus();
    }
  });
  n.show();
}

/* ---------------- window ---------------- */

function createWindow() {
  const { screen } = require("electron");
  const area = screen.getPrimaryDisplay().workArea;
  const width = Math.max(360, Math.round(area.width * 0.2));
  win = new BrowserWindow({
    width,
    height: area.height,
    x: area.x + area.width - width,
    y: area.y,
    frame: false,
    alwaysOnTop: true,
    skipTaskbar: false,
    resizable: true,
    backgroundColor: "#16181d",
    icon: path.join(__dirname, "icon.png"),
    webPreferences: { preload: path.join(__dirname, "preload.cjs"), contextIsolation: true, nodeIntegration: false },
  });
  win.setAlwaysOnTop(true, "screen-saver");
  win.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  win.loadFile(path.join(__dirname, "ui.html"));
}

function createTray() {
  try {
    tray = new Tray(path.join(__dirname, "icon.png"));
    tray.setToolTip("Sentinel");
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: "Mostra Sentinel", click: () => (win ? (win.show(), win.focus()) : createWindow()) },
        { label: "Esci", click: () => app.exit(0) },
      ]),
    );
    tray.on("click", () => (win ? (win.isVisible() ? win.hide() : win.show()) : createWindow()));
  } catch {}
}

/* ---------------- ipc ---------------- */

ipcMain.handle("scan", async () => {
  const [processes, connections, files] = await Promise.all([scanProcesses(), scanConnections(), scanFiles()]);
  const danger = [
    ...processes.filter((p) => p.judgement.level === "danger").map((p) => ({ what: `Processo ${p.name}`, why: p.judgement.reasons[0] })),
    ...connections.filter((c) => c.judgement.level === "danger").map((c) => ({ what: `Connessione ${c.remote}:${c.rport}`, why: c.judgement.reasons[0] })),
    ...files.filter((f) => f.judgement.level === "danger").map((f) => ({ what: `File ${f.name}`, why: f.judgement.reasons[0] })),
  ];
  if (danger.length) alertThreat("Sentinel · Minaccia rilevata", `${danger[0].what}: ${danger[0].why}${danger.length > 1 ? ` (+${danger.length - 1} altre)` : ""}`);
  return { processes, connections, files, feed: { total: feed.total, updatedAt: feed.updatedAt }, platform: process.platform };
});

ipcMain.handle("refresh-feeds", () => refreshFeeds());
ipcMain.handle("kill", (_e, { pid, name }) => killProcess(pid, name));
ipcMain.handle("block-ip", (_e, { ip }) => blockIp(ip));
ipcMain.handle("block-program", (_e, { path: p, name }) => blockProgram(p, name));
ipcMain.handle("quarantine", async (_e, { path: p }) => {
  const choice = await dialog.showMessageBox(win, {
    type: "warning",
    buttons: ["Metti in quarantena", "Annulla"],
    defaultId: 1,
    message: "Spostare il file in quarantena?",
    detail: p,
  });
  if (choice.response !== 0) return { ok: false, message: "Annullato." };
  return quarantineFile(p);
});
ipcMain.handle("defender-scan", (_e, { target } = {}) => defenderScan(target));
ipcMain.handle("open-folder", (_e, { path: p }) => shell.showItemInFolder(p));
ipcMain.handle("win", (_e, { action }) => {
  if (!win) return;
  if (action === "hide") win.hide();
  if (action === "quit") app.exit(0);
  if (action === "top") {
    const next = !win.isAlwaysOnTop();
    win.setAlwaysOnTop(next, "screen-saver");
    return next;
  }
  return win.isAlwaysOnTop();
});

app.whenReady().then(() => {
  createWindow();
  createTray();
  refreshFeeds();
  setInterval(refreshFeeds, 30 * 60 * 1000);
  app.setLoginItemSettings({ openAtLogin: true });
});
app.on("window-all-closed", () => {});
