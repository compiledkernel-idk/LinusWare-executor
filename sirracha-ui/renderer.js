const { ipcRenderer } = require('electron');

// Window controls
window.electron = {
    minimize: () => ipcRenderer.send('minimize'),
    maximize: () => ipcRenderer.send('maximize'),
    close: () => ipcRenderer.send('close')
};

// State
let currentPid = null;
let isAttached = false;

// Elements
const statusIndicator = document.getElementById('statusIndicator');
const statusText = document.getElementById('statusText');
const attachBtn = document.getElementById('attachBtn');
const executeBtn = document.getElementById('executeBtn');
const editor = document.getElementById('editor');
const lineNumbers = document.getElementById('lineNumbers');
const consoleEl = document.getElementById('console');

// Console logging
function log(message, type = 'info') {
    const line = document.createElement('div');
    line.className = `console-line ${type}`;

    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    line.textContent = `[${time}] ${message}`;

    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

function clearConsole() {
    consoleEl.innerHTML = '';
    log('Console cleared', 'info');
}

// Status updates
function setStatus(status, text) {
    statusIndicator.className = 'status-indicator ' + status;
    statusText.textContent = text;
}

// Editor State
let updateTimer = null;

// Helper to escape HTML safely
function escapeHtml(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

// Optimised update with debounce
function update(text) {
    let result_element = document.querySelector("#highlighting-content");

    if (updateTimer) clearTimeout(updateTimer);
    updateTimer = setTimeout(() => {
        // Handle final newlines
        if (text[text.length - 1] == "\n") {
            text += " ";
        }
        // Syntax Highlight proper
        result_element.innerHTML = highlight(text);
        updateTimer = null;
    }, 10);
}

// Immediate update for loading scripts
function setEditorContent(text) {
    editor.value = text;
    let result_element = document.querySelector("#highlighting-content");
    if (text[text.length - 1] == "\\n") { text += " "; }

    // Update view
    result_element.innerHTML = highlight(text);
    updateLineNumbers();
}

function syncScroll(element) {
    let result_element = document.querySelector("#highlighting");
    requestAnimationFrame(() => {
        result_element.scrollTop = element.scrollTop;
        result_element.scrollLeft = element.scrollLeft;
    });
}

function checkTab(element, event) {
    let code = element.value;
    if (event.key == "Tab") {
        /* Tab key pressed */
        event.preventDefault();
        let before_tab = code.slice(0, element.selectionStart);
        let after_tab = code.slice(element.selectionEnd, element.value.length);
        let cursor_pos = element.selectionStart + 2;
        element.value = before_tab + "  " + after_tab;
        element.selectionStart = cursor_pos;
        element.selectionEnd = cursor_pos;
        setEditorContent(element.value);
    }
}

// Safer Lua Syntax Highlighter
function highlight(text) {
    // 1. Escape HTML entities first so we don't break our own tags later
    text = escapeHtml(text);

    // 2. Tokenize regex
    const tokenRegex = /(--\[\[[\s\S]*?\]\]|--.*)|(".*?"|'.*?'|\[\[[\s\S]*?\]\])|(\b\d+(\.\d+)?\b)|(\b(and|break|do|else|elseif|end|false|for|function|if|in|local|nil|not|or|repeat|return|then|true|until|while)\b)|(\b(print|warn|error|assert|collectgarbage|require|module|getfenv|setfenv|loadstring|loadfile|dofile|pcall|xpcall|tostring|tonumber|game|workspace|script|math|string|table)\b)/g;

    return text.replace(tokenRegex, function (match, comment, string, number, num_dummy, keyword, kw_dummy, builtin) {
        if (comment) return `<span class="token comment">${comment}</span>`;
        if (string) return `<span class="token string">${string}</span>`;
        if (number) return `<span class="token number">${number}</span>`;
        if (keyword) return `<span class="token keyword">${keyword}</span>`;
        if (builtin) return `<span class="token builtin">${builtin}</span>`;
        return match;
    });
}

// Initial update - important!
window.addEventListener('DOMContentLoaded', () => {
    setEditorContent(editor.value);
});

// Initial update
setEditorContent(editor.value);

// Update line numbers
function updateLineNumbers() {
    const lines = editor.value.split('\\n').length;
    lineNumbers.innerHTML = Array.from({ length: lines }, (_, i) => i + 1).join('<br>');
}

editor.addEventListener('input', updateLineNumbers);
editor.addEventListener('scroll', () => {
    // using syncScroll onscroll attribute instead
});

// Attach function
async function attach() {
    attachBtn.disabled = true;
    setStatus('connecting', 'Connecting...');
    log('Looking for Sober process...', 'info');

    // Find Sober
    let pid = await ipcRenderer.invoke('find-sober');

    if (!pid) {
        log('Sober not found, launching...', 'warning');
        await ipcRenderer.invoke('launch-sober');

        // Wait for Sober to start
        for (let i = 0; i < 30; i++) {
            await new Promise(r => setTimeout(r, 500));
            pid = await ipcRenderer.invoke('find-sober');
            if (pid) break;
        }
    }

    if (!pid) {
        setStatus('', 'Not Connected');
        log('Failed to find Sober process', 'error');
        attachBtn.disabled = false;
        return;
    }

    log(`Found Sober PID: ${pid}`, 'success');
    currentPid = pid;

    // Inject
    log('Injecting library...', 'info');
    const result = await ipcRenderer.invoke('inject', pid);

    if (!result.success) {
        log('Injection failed: ' + result.output, 'error');
        setStatus('', 'Injection Failed');
        attachBtn.disabled = false;
        return;
    }

    log('Injection successful!', 'success');

    // Wait for ready signal
    log('Waiting for ready signal...', 'info');
    for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 500));
        const ready = await ipcRenderer.invoke('check-ready', pid);
        if (ready) {
            log('Ready signal received!', 'success');
            log(ready.split('\n').filter(l => l).join(', '), 'info');

            setStatus('connected', 'Connected');
            isAttached = true;
            executeBtn.disabled = false;
            attachBtn.textContent = '🔗 Reattach';
            attachBtn.disabled = false;
            return;
        }
    }

    log('Timeout waiting for ready signal', 'warning');
    setStatus('', 'Partially Connected');
    attachBtn.disabled = false;
}

// Execute function
async function execute() {
    if (!currentPid || !isAttached) {
        log('Not attached to Sober', 'error');
        return;
    }

    const script = editor.value;
    if (!script.trim()) {
        log('No script to execute', 'warning');
        return;
    }

    executeBtn.disabled = true;
    log(`Executing script (${script.length} bytes)...`, 'info');

    const output = await ipcRenderer.invoke('execute-script', currentPid, script);

    if (output.startsWith('Error:')) {
        log(output, 'error');
    } else {
        log(output || 'Script executed successfully', 'success');
    }

    executeBtn.disabled = false;
}

// Clear editor
function clearEditor() {
    editor.value = '';
    updateLineNumbers();
}

// Example scripts
const examples = {
    hello: 'print("Hello from Sirracha Executor!")\nprint("Version 2.0")',
    speed: `-- Speed Hack
local player = game.Players.LocalPlayer
local humanoid = player.Character:WaitForChild("Humanoid")
humanoid.WalkSpeed = 100
print("Speed set to 100!")`,
    fly: `-- Fly Script
local player = game.Players.LocalPlayer
local character = player.Character
local humanoid = character:WaitForChild("Humanoid")

-- Enable flying
humanoid.PlatformStand = true
print("Fly mode enabled!")`
};

function loadExample(name) {
    if (examples[name]) {
        editor.value = examples[name];
        updateLineNumbers();
        log(`Loaded example: ${name}`, 'info');
    }
}

function loadScript() {
    // Would open file dialog
    log('Script loading not yet implemented', 'warning');
}

// Initialize
updateLineNumbers();
log('Ready. Click Attach to connect to Sober.', 'info');
