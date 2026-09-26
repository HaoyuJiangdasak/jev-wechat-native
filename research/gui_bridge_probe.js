/* Bounded diagnostic bridge. CONFIG is injected by the guarded Python host. */
'use strict';

if (Process.id !== CONFIG.pid) throw Error('PID mismatch');
if (Process.arch !== 'x64' || Process.pointerSize !== 8) throw Error('Architecture mismatch');
const image = Process.getModuleByName(CONFIG.moduleName);
if (image.path.toLowerCase() !== CONFIG.dllPath.toLowerCase()) throw Error('Unexpected module path');
const prologueAddress = image.base.add(CONFIG.buildRva);
const actual = Array.from(new Uint8Array(prologueAddress.readByteArray(CONFIG.prologue.length)));
if (!actual.every((value, index) => value === CONFIG.prologue[index])) throw Error('Verified code bytes changed');

const user32 = Process.getModuleByName('user32.dll');
// Official Win32 signatures: DWORD(HWND,LPDWORD), LONG_PTR(HWND,int),
// UINT(LPCWSTR), BOOL(HWND,UINT,WPARAM,LPARAM). This script requires x64.
const getWindowThreadProcessId = new NativeFunction(
  user32.getExportByName('GetWindowThreadProcessId'), 'uint32', ['pointer', 'pointer'], 'win64');
const getWindowLongPtrW = new NativeFunction(
  user32.getExportByName('GetWindowLongPtrW'), 'pointer', ['pointer', 'int'], 'win64');
const registerWindowMessageW = new NativeFunction(
  user32.getExportByName('RegisterWindowMessageW'), 'uint32', ['pointer'], 'win64');
const postMessageW = new NativeFunction(
  user32.getExportByName('PostMessageW'), 'int', ['pointer', 'uint32', 'pointer', 'pointer'], 'win64');

const hwnd = ptr(CONFIG.hwnd);
const pidOut = Memory.alloc(4);
pidOut.writeU32(0);
const guiThreadId = getWindowThreadProcessId(hwnd, pidOut);
if (guiThreadId === 0 || pidOut.readU32() !== CONFIG.pid) throw Error('HWND is not owned by the verified PID');
const wndProc = getWindowLongPtrW(hwnd, -4); // GWLP_WNDPROC
if (wndProc.isNull()) throw Error('GetWindowLongPtrW returned NULL');
const range = Process.findRangeByAddress(wndProc);
if (range === null || !range.protection.includes('x')) throw Error('WndProc is not an executable address');
const wndProcModule = Process.findModuleByAddress(wndProc);
if (wndProcModule === null && !CONFIG.selfTest) throw Error('Unidentified WndProc module');

const messageId = registerWindowMessageW(Memory.allocUtf16String(CONFIG.messageName));
if (messageId < 0xc000 || messageId > 0xffff) throw Error('RegisterWindowMessageW failed');
const nonce = ptr(CONFIG.nonce);
const stats = {event: 'ready', targetPid: Process.id, hwnd: hwnd.toString(),
  expectedGuiThreadId: guiThreadId, messageId, posted: 0, hits: 0,
  threadIds: [], sequences: [], callbacksOnGuiThread: true, detachedHook: false,
  wndProcModule: wndProcModule === null ? 'self-test callback allocation' : wndProcModule.name,
  wndProcRva: wndProcModule === null ? null : wndProc.sub(wndProcModule.base).toString(),
  timedOut: false, passed: false};
let listener = null;
let watchdog = null;
let finished = false;

function finish(reason) {
  if (finished) return stats;
  finished = true;
  if (watchdog !== null) clearTimeout(watchdog);
  if (listener !== null) {
    listener.detach();
    listener = null;
    stats.detachedHook = true;
  }
  stats.event = 'done';
  stats.reason = reason;
  stats.timedOut = reason === 'deadline';
  stats.passed = stats.posted === 3 && stats.hits === 3 &&
    stats.sequences.length === 3 && stats.callbacksOnGuiThread && stats.detachedHook;
  send({...stats});
  return stats;
}

listener = Interceptor.attach(wndProc, {
  onEnter(args) {
    if (finished || !args[0].equals(hwnd) || args[1].toUInt32() !== messageId || !args[3].equals(nonce)) return;
    const sequence = args[2].toUInt32();
    if (sequence < 1 || sequence > 3 || stats.sequences.includes(sequence)) return;
    stats.hits++;
    stats.sequences.push(sequence);
    if (!stats.threadIds.includes(this.threadId)) stats.threadIds.push(this.threadId);
    if (this.threadId !== guiThreadId) stats.callbacksOnGuiThread = false;
    send({event: 'callback', sequence, threadId: this.threadId, expectedGuiThreadId: guiThreadId});
    if (stats.hits === 3) setImmediate(() => finish('three_callbacks'));
  }
});
Interceptor.flush();
watchdog = setTimeout(() => finish('deadline'), 8000);
rpc.exports = {stop() { return finish('host_stop'); }};
send({...stats});

for (let sequence = 1; sequence <= 3; sequence++) {
  // A registered diagnostic window message is not a chat message or input action.
  if (postMessageW(hwnd, messageId, ptr(sequence), nonce) === 0) {
    finish('PostMessageW_failed');
    break;
  }
  stats.posted++;
}
