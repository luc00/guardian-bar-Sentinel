const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, shell, dialog } = require("electron");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { execFile } = require("child_process");
const security = require("./security.cjs");

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

function ps(script, timeout = 90000) {
  return run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + script], timeout);
}

// Runs a command elevated (UAC prompt) — needed for firewall rules and killing protected processes.
function psElevated(inner) {
  const wrapped = `$ErrorActionPreference='Stop'; try { ${inner}; exit 0 } catch { exit 1 }`;
  const encoded = Buffer.from(wrapped, "utf16le").toString("base64");
  return ps(`$ErrorActionPreference='Stop'; $p=Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-EncodedCommand','${encoded}'; if ($p.ExitCode -ne 0) { throw 'Operazione non riuscita' }`, 120000);
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

async function collect(script) {
  const r = await ps("$ErrorActionPreference='Stop'; " + script);
  if (!r.ok) throw new Error('Accesso ai dati non riuscito: ' + r.err.slice(0, 240));
  const text = r.out.trim();
  if (!text || text === 'null') return [];
  try { const v = JSON.parse(text); return Array.isArray(v) ? v : [v]; }
  catch { throw new Error('Risposta di Windows non leggibile.'); }
}

async function scanProcesses() {
  const rows = await collect(`
$commands=@{}; Get-CimInstance Win32_Process | ForEach-Object { $commands[[int]$_.ProcessId]=$_.CommandLine }
$signatures=@{}
@(Get-Process | ForEach-Object {
  $p=$_; $pth=$null; $sig=$null; $company=$null
  try { $pth=$p.Path; $company=$p.Company } catch {}
  if ($pth) {
    if (-not $signatures.ContainsKey($pth)) {
      try { $signatures[$pth]=(Get-AuthenticodeSignature -LiteralPath $pth -ErrorAction Stop).Status.ToString() }
      catch { $signatures[$pth]='UnknownError' }
    }
    $sig=$signatures[$pth]
  }
  [PSCustomObject]@{ pid=$p.Id; name=$p.ProcessName; path=$pth; cmd=$commands[[int]$p.Id];
    company=$company; cpuSeconds=[math]::Round($p.CPU,1); mem=[math]::Round($p.WorkingSet64/1MB,1); signature=$sig }
}) | ConvertTo-Json -Compress -Depth 4`);
  return rows.map(p => ({ ...p, judgement: security.judgeProcess(p) }));
}

async function scanConnections() {
  return collect(`
$procs=@{}; Get-Process | ForEach-Object { $procs[$_.Id]=$_.ProcessName }
$tcp=@(Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' } | ForEach-Object {
  [PSCustomObject]@{ protocol='TCP'; local=$_.LocalAddress; lport=$_.LocalPort; remote=$_.RemoteAddress; rport=$_.RemotePort;
    state=$_.State.ToString(); pid=$_.OwningProcess; name=$procs[[int]$_.OwningProcess] }
})
$udp=@(Get-NetUDPEndpoint | ForEach-Object {
  [PSCustomObject]@{ protocol='UDP'; local=$_.LocalAddress; lport=$_.LocalPort; remote=''; rport=0;
    state='Listen'; pid=$_.OwningProcess; name=$procs[[int]$_.OwningProcess] }
})
@($tcp + $udp) | ConvertTo-Json -Compress -Depth 4`);
}

async function scanFiles() {
  // Resolve redirected Windows folders, include OneDrive Desktop when configured.
  return (await collect(`
$folders=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders'
$downloads=[Environment]::ExpandEnvironmentVariables($folders.'{374DE290-123F-4565-9164-39C4925E467B}')
$dirs=@($downloads,[Environment]::GetFolderPath('Desktop'),[IO.Path]::GetTempPath()) | Where-Object { $_ } | Select-Object -Unique
$cutoff=(Get-Date).AddDays(-7)
$items=@(foreach ($dir in $dirs) {
  if (Test-Path -LiteralPath $dir) {
    Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop | Where-Object { $_.LastWriteTime -gt $cutoff }
  }
})
@($items | Sort-Object LastWriteTime -Descending | Select-Object -First 100 | ForEach-Object {
  $f=$_; $sig=$null; $hash=$null; $error=$null
  if ($f.Extension -match '^\\.(exe|scr|bat|cmd|ps1|vbs|js|jar|msi|hta|lnk|dll|pif|com|reg)$') {
    try { $sig=(Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop).Status.ToString() } catch { $sig='UnknownError' }
    if ($f.Length -le 50MB) {
      try { $hash=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $error='File non leggibile' }
    }
  }
  [PSCustomObject]@{ name=$f.Name; path=$f.FullName; dir=$f.DirectoryName; size=$f.Length;
    mtime=([DateTimeOffset]$f.LastWriteTimeUtc).ToUnixTimeMilliseconds(); signature=$sig; sha256=$hash; error=$error }
}) | ConvertTo-Json -Compress -Depth 4`)).map(f => ({ ...f, judgement: security.judgeFile(f) }));
}

let snapshot = null;
let pendingScan = null;
async function performScan() {
  if (pendingScan) return pendingScan;
  pendingScan = (async () => {
    const startedAt = Date.now();
    const jobs = isWin ? await Promise.allSettled([scanProcesses(), scanConnections(), scanFiles()]) : [];
    const sections = {}; const values = {};
    ['processes','connections','files'].forEach((key, idx) => {
      const job = jobs[idx];
      values[key] = job?.status === 'fulfilled' ? job.value : [];
      sections[key] = { ok: job?.status === 'fulfilled', error: !isWin ? 'Raccolta disponibile solo su Windows.' : job?.status === 'rejected' ? job.reason.message : null };
    });
    const owners = new Map(values.processes.map(p => [p.pid, p]));
    values.connections = values.connections.map(c => ({ ...c, judgement: security.judgeConnection(c, feed.ips, owners.get(c.pid)) }));
    snapshot = { ...values, sections, startedAt, scannedAt: Date.now(), platform: process.platform,
      feed: { total: feed.total, updatedAt: feed.updatedAt }, fileScope: 'Ultimi 7 giorni · Download, Desktop, Temp · max 100 file · nessuna sottocartella' };
    const danger = [...values.processes, ...values.connections, ...values.files].filter(i => i.judgement.level === 'danger');
    if (danger.length) alertThreat('Sentinel · Rischio elevato', `${danger[0].name || danger[0].remote}: ${danger[0].judgement.reasons[0]}`);
    if (win && !win.isDestroyed()) win.webContents.send('snapshot', snapshot);
    return snapshot;
  })();
  try { return await pendingScan; } finally { pendingScan = null; }
}

/* ---------------- actions ---------------- */

async function killProcess(pid, name) {
  const target = snapshot?.processes.find(p => p.pid === pid);
  if (!Number.isInteger(pid) || pid <= 4 || pid === process.pid || !target || /^(csrss|wininit|winlogon|lsass|services|smss)$/i.test(target.name))
    return { ok: false, message: 'Processo non selezionabile o essenziale per Windows.' };
  const choice = await dialog.showMessageBox(win, { type: 'warning', buttons: ['Chiudi processo', 'Annulla'], defaultId: 1, cancelId: 1, message: `Chiudere ${target.name} (PID ${pid})?`, detail: 'I dati non salvati potrebbero andare persi.' });
  if (choice.response !== 0) return { ok: false, message: 'Annullato.' };
  // Recheck executable identity to avoid acting on a reused PID.
  const expected = String(target.path || '').replace(/'/g, "''");
  if (!expected) return { ok: false, message: 'Percorso non leggibile: chiusura non consentita.' };
  const stop = `$ErrorActionPreference='Stop'; $p=Get-Process -Id ${pid}; if ($p.Path -ne '${expected}') { throw 'Il processo è cambiato' }; Stop-Process -Id ${pid} -Force -ErrorAction Stop`;
  let r = await ps(stop);
  if (!r.ok) r = await psElevated(stop);
  return { ok: r.ok, message: r.ok ? `Processo ${name} chiuso.` : `Non sono riuscito a chiudere ${name}. Potrebbe essere protetto dal sistema.` };
}

async function blockIp(ip) {
  if (!security.validIp(ip) || ip === "0.0.0.0" || ip === "::") return { ok: false, message: "Indirizzo non valido." };
  const rule = `Sentinel blocco ${ip}`;
  const r = await psElevated(
    `New-NetFirewallRule -DisplayName '${rule}' -Direction Outbound -RemoteAddress ${ip} -Action Block -Profile Any; ` +
      `New-NetFirewallRule -DisplayName '${rule} (in)' -Direction Inbound -RemoteAddress ${ip} -Action Block -Profile Any`,
  );
  return { ok: r.ok, message: r.ok ? `Collegamenti con ${ip} bloccati nel firewall di Windows.` : "Blocco non riuscito: servono i permessi di amministratore." };
}

async function blockProgram(exePath, name) {
  if (!snapshot?.processes.some(p => p.path === exePath)) return { ok: false, message: "Percorso del programma sconosciuto." };
  const safe = exePath.replace(/'/g, "''");
  const r = await psElevated(
    `New-NetFirewallRule -DisplayName 'Sentinel blocco ${String(name).replace(/'/g, "''")}' -Direction Outbound -Program '${safe}' -Action Block -Profile Any`,
  );
  return { ok: r.ok, message: r.ok ? `${name} non può più collegarsi a internet.` : "Blocco non riuscito: servono i permessi di amministratore." };
}

async function quarantineFile(filePath) {
  if (!snapshot?.files.some(f => f.path === filePath)) return { ok: false, message: 'File non presente nell’ultima scansione.' };
  const qdir = path.join(app.getPath("userData"), "quarantena");
  try {
    fs.mkdirSync(qdir, { recursive: true });
    const dest = path.join(qdir, `${Date.now()}_${path.basename(filePath)}.bloccato`);
    fs.renameSync(filePath, dest);
    const acl = await run('icacls.exe', [dest, '/inheritance:r', '/deny', '*S-1-1-0:(RX,X)']);
    if (!acl.ok) return { ok: false, message: 'File spostato, ma blocco dei permessi non riuscito. Non aprirlo.', dest };
    return { ok: true, message: `File messo in quarantena. Copia bloccata in ${qdir}.`, dest };
  } catch (e) {
    return { ok: false, message: `Quarantena non riuscita: ${e.message}` };
  }
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
    webPreferences: { preload: path.join(__dirname, "preload.cjs"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.setAlwaysOnTop(true, "screen-saver");
  win.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', event => event.preventDefault());
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

ipcMain.handle("scan", () => performScan());
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
  refreshFeeds().then(() => performScan());
  setInterval(() => performScan(), 30000);
  setInterval(refreshFeeds, 30 * 60 * 1000);
  app.setLoginItemSettings({ openAtLogin: true });
});
app.on("window-all-closed", () => {});
