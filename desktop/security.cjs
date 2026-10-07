const net = require('node:net');
const riskyExt = /\.(exe|scr|bat|cmd|ps1|vbs|js|jar|msi|hta|lnk|dll|pif|com|reg)$/i;
const suspectDir = /\\(temp|downloads|public)\\/i;
const tools = /(?:^|\\)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe$/i;
const sensitivePorts = new Map([[3389,'Desktop remoto'],[445,'Condivisione Windows'],[23,'Telnet non cifrato'],[21,'FTP non cifrato'],[5900,'Controllo remoto VNC'],[4444,'Porta insolita'],[1337,'Porta insolita'],[6667,'IRC']]);

function result(score, reasons, unknown = false) {
  return { level: score >= 5 ? 'danger' : score > 0 ? 'warn' : unknown ? 'unknown' : 'safe', reasons: reasons.length ? reasons : ['Nessun indicatore sospetto rilevato; non è una garanzia di sicurezza.'] };
}
function judgeProcess(p) {
  let score = 0; const reasons = [];
  if (!p.path) return result(0, ['Percorso e firma non accessibili: valutazione incompleta.'], true);
  if (suspectDir.test(p.path)) { score += 2; reasons.push('Programma eseguito da una cartella temporanea o di download.'); }
  if (p.signature === 'NotSigned') { score++; reasons.push('Firma digitale assente.'); }
  else if (['HashMismatch','NotTrusted'].includes(p.signature)) { score += 4; reasons.push('Firma alterata o non attendibile.'); }
  if (tools.test(p.path) && /(?:-enc(?:odedcommand)?\b|frombase64string|downloadstring|invoke-expression|\biex\b)/i.test(p.cmd || '')) { score += 3; reasons.push('Interprete con comando codificato o download/esecuzione dinamica.'); }
  if (tools.test(p.path) && suspectDir.test(p.cmd || '')) { score += 2; reasons.push('Interprete di sistema usato su una cartella a rischio.'); }
  if (p.signature === 'Valid') reasons.push('Firma digitale valida: non esclude comportamenti dannosi.');
  const unknown = !p.signature || ['UnknownError','NotSupported'].includes(p.signature);
  if (unknown) reasons.push('Firma non verificabile.');
  return result(score, reasons, unknown);
}
function localOnly(ip) {
  return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/i.test(String(ip));
}
function judgeConnection(c, ips = new Set(), owner) {
  let score = 0; const reasons = [];
  const listening = c.state === 'Listen' || c.protocol === 'UDP';
  if (!listening && ips.has(c.remote)) { score += 6; reasons.push('IP remoto presente nel feed di URL dannose; possibile infrastruttura condivisa.'); }
  if (listening) {
    const wildcard = c.local === '0.0.0.0' || c.local === '::';
    if (wildcard) { score++; reasons.push('In ascolto su tutte le interfacce; accessibilità esterna dipende da firewall e router.'); }
    if (sensitivePorts.has(Number(c.lport)) && !/^127\.|^::1$/.test(c.local)) { score += 2; reasons.push(`${sensitivePorts.get(Number(c.lport))}: verificare se il servizio è necessario.`); }
    if (!reasons.length) reasons.push('Porta locale in ascolto; non prova un accesso da Internet.');
  } else if (!localOnly(c.remote) && ![80,443,53,123,993,587,22].includes(Number(c.rport))) {
    score++; reasons.push('Connessione su porta non comune; può essere legittima.');
  }
  if (owner?.judgement.level === 'danger') { score += 3; reasons.push('Il processo associato presenta indicatori di rischio elevato.'); }
  if (!owner) reasons.push('Processo associato non leggibile.');
  return result(score, reasons, !owner);
}
function judgeFile(f) {
  let score = 0; const reasons = [];
  if (riskyExt.test(f.name)) { score++; reasons.push('File eseguibile o script: può eseguire comandi.'); }
  if (/\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\.(exe|scr|js|bat|cmd|vbs)$/i.test(f.name)) { score += 4; reasons.push('Doppia estensione che può mascherare un eseguibile.'); }
  if (/[\u202e\u200f]/.test(f.name)) { score += 5; reasons.push('Caratteri invisibili che possono mascherare il nome.'); }
  if (riskyExt.test(f.name) && /\\temp\\/i.test(f.dir)) { score++; reasons.push('Eseguibile in una cartella temporanea; può essere un installer legittimo.'); }
  if (['HashMismatch','NotTrusted'].includes(f.signature)) { score += 4; reasons.push('Firma digitale alterata o non attendibile.'); }
  if (f.signature === 'NotSigned') reasons.push('Firma digitale assente.');
  if (f.signature === 'Valid') reasons.push('Firma digitale valida; non garantisce l’assenza di malware.');
  if (f.sha256) reasons.push(`SHA-256: ${f.sha256}`);
  const unknown = !!f.error || (riskyExt.test(f.name) && (!f.signature || ['UnknownError','NotSupported'].includes(f.signature)));
  if (unknown) reasons.push('Analisi parziale: firma o contenuto non accessibili.');
  return result(score, reasons, unknown);
}
module.exports = { judgeProcess, judgeConnection, judgeFile, riskyExt, localOnly, validIp: ip => net.isIP(String(ip)) !== 0 };