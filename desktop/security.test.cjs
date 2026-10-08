const { test } = require('node:test');
const assert = require('node:assert/strict');
const s = require('./security.cjs');
test('CPU cumulative time is not a malware indicator', () => {
  assert.equal(s.judgeProcess({ path: 'C:\\Windows\\System32\\svchost.exe', signature: 'Valid', cpuSeconds: 900 }).level, 'safe');
});
test('Inaccessible processes are not marked safe', () => {
  assert.equal(s.judgeProcess({ path: null }).level, 'unknown');
});
test('Unsigned downloads merit attention, not confirmed malware', () => {
  assert.equal(s.judgeProcess({ path: 'C:\\Users\\me\\Downloads\\setup.exe', signature: 'NotSigned' }).level, 'warn');
});
test('Encoded interpreter with temporary payload merits high risk', () => {
  assert.equal(s.judgeProcess({ path: 'C:\\Windows\\System32\\powershell.exe', signature: 'Valid', cmd: '-enc AAA C:\\Users\\me\\Temp\\x.ps1' }).level, 'danger');
});
test('Wildcard RDP is a warning, not proof of exposure', () => {
  assert.equal(s.judgeConnection({ local: '0.0.0.0', lport: 3389, protocol: 'TCP', state: 'Listen' }, new Set(), { judgement: { level: 'safe' } }).level, 'warn');
});
test('Threat IP overrides common-port assumption', () => {
  assert.equal(s.judgeConnection({ remote: '1.2.3.4', rport: 443, state: 'Established' }, new Set(['1.2.3.4'])).level, 'danger');
});
test('Valid signature does not erase deceptive extension', () => {
  assert.equal(s.judgeFile({ name: 'invoice.pdf.exe', dir: 'C:\\Downloads', signature: 'Valid' }).level, 'danger');
});
test('Temporary installer is not automatically malware', () => {
  assert.equal(s.judgeFile({ name: 'setup.exe', dir: 'C:\\Temp', signature: 'Valid' }).level, 'warn');
});
test('IP validation rejects malformed addresses', () => {
  assert.equal(s.validIp('1.2.3.999'), false);
  assert.equal(s.validIp('::1'), true);
});