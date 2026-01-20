const { invoke } = window.__TAURI__;

let isConnected = false;
let editor = null;

const LUAU_KEYWORDS = [
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function',
    'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then',
    'true', 'until', 'while', 'continue', 'type', 'export'
];

const LUAU_BUILTINS = [
    'print', 'warn', 'error', 'game', 'workspace', 'script', 'math', 'string',
    'table', 'pcall', 'xpcall', 'tostring', 'tonumber', 'require', 'typeof',
    'setmetatable', 'getmetatable', 'pairs', 'ipairs', 'next', 'select',
    'unpack', 'rawget', 'rawset', 'Instance', 'Vector3', 'CFrame', 'Color3',
    'UDim2', 'Enum', 'task', 'wait', 'spawn', 'delay', 'tick', 'time',
    'assert', 'collectgarbage', 'coroutine', 'debug', 'getfenv', 'setfenv',
    'loadstring', 'newproxy', 'os', 'utf8'
];

const ROBLOX_SERVICES = [
    'Players', 'Workspace', 'ReplicatedStorage', 'ServerStorage', 'ServerScriptService',
    'StarterGui', 'StarterPack', 'StarterPlayer', 'Lighting', 'SoundService',
    'TweenService', 'UserInputService', 'RunService', 'Debris', 'HttpService',
    'MarketplaceService', 'DataStoreService', 'MessagingService', 'TeleportService',
    'LocalPlayer', 'Character', 'Humanoid', 'HumanoidRootPart', 'Camera'
];

const ROBLOX_METHODS = [
    'GetService', 'FindFirstChild', 'WaitForChild', 'GetChildren', 'GetDescendants',
    'Clone', 'Destroy', 'Remove', 'ClearAllChildren', 'IsA', 'GetPropertyChangedSignal',
    'Connect', 'Disconnect', 'Fire', 'Wait', 'Once', 'new', 'fromRGB', 'fromHSV',
    'Lerp', 'Magnitude', 'Unit', 'Dot', 'Cross', 'lookAt', 'Angles', 'Play', 'Stop',
    'LoadAnimation', 'MoveTo', 'SetPrimaryPartCFrame', 'GetPrimaryPartCFrame',
    'CreateTween', 'GetMouse', 'GetTouchingParts', 'Raycast', 'GetPartBoundsInBox'
];

document.addEventListener('DOMContentLoaded', () => {
    let dots = 0;
    const dotsEl = document.getElementById('loading-dots');
    const dotsInterval = setInterval(() => {
        dots = (dots + 1) % 4;
        dotsEl.textContent = '.'.repeat(dots);
    }, 400);

    setTimeout(() => {
        clearInterval(dotsInterval);
        document.getElementById('loading-screen').classList.add('hidden');
        document.getElementById('app').classList.remove('hidden');
        initMonaco();
        startStatusCheck();
    }, 3000);

    initNavigation();
    initActions();
    initSettings();
});

function initMonaco() {
    require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs' } });

    require(['vs/editor/editor.main'], function () {
        monaco.languages.register({ id: 'luau' });

        monaco.languages.setMonarchTokensProvider('luau', {
            keywords: LUAU_KEYWORDS,
            builtins: LUAU_BUILTINS,
            operators: ['+', '-', '*', '/', '%', '^', '#', '==', '~=', '<=', '>=', '<', '>', '=', '.', ':', '..'],

            tokenizer: {
                root: [
                    [/--\[\[[\s\S]*?\]\]/, 'comment'],
                    [/--.*$/, 'comment'],
                    [/\[\[[\s\S]*?\]\]/, 'string'],
                    [/"([^"\\]|\\.)*"/, 'string'],
                    [/'([^'\\]|\\.)*'/, 'string'],
                    [/\b\d+(\.\d+)?\b/, 'number'],
                    [/\b(true|false|nil)\b/, 'keyword'],
                    [/\b(and|break|do|else|elseif|end|for|function|if|in|local|not|or|repeat|return|then|until|while|continue|type|export)\b/, 'keyword'],
                    [/\b(print|warn|error|game|workspace|script|math|string|table|pcall|xpcall|tostring|tonumber|require|typeof|setmetatable|getmetatable|pairs|ipairs|next|select|unpack|rawget|rawset|Instance|Vector3|CFrame|Color3|UDim2|Enum|task|wait|spawn|delay|tick|time|assert)\b/, 'type'],
                    [/[a-zA-Z_]\w*(?=\s*\()/, 'function'],
                    [/[a-zA-Z_]\w*/, 'identifier'],
                    [/[{}()\[\]]/, '@brackets'],
                    [/[;,.]/, 'delimiter'],
                ]
            }
        });

        monaco.editor.defineTheme('luau-dark', {
            base: 'vs-dark',
            inherit: true,
            rules: [
                { token: 'keyword', foreground: 'c586c0', fontStyle: 'bold' },
                { token: 'type', foreground: '4ec9b0' },
                { token: 'function', foreground: 'dcdcaa' },
                { token: 'string', foreground: 'ce9178' },
                { token: 'number', foreground: 'b5cea8' },
                { token: 'comment', foreground: '6a9955', fontStyle: 'italic' },
                { token: 'identifier', foreground: '9cdcfe' },
            ],
            colors: {
                'editor.background': '#0a0a0a',
                'editor.foreground': '#d4d4d4',
                'editor.lineHighlightBackground': '#1a1a1a',
                'editorCursor.foreground': '#ffffff',
                'editor.selectionBackground': '#264f78',
                'editorLineNumber.foreground': '#555555',
            }
        });

        const allCompletions = [
            ...LUAU_KEYWORDS.map(k => ({ label: k, kind: monaco.languages.CompletionItemKind.Keyword, insertText: k })),
            ...LUAU_BUILTINS.map(b => ({ label: b, kind: monaco.languages.CompletionItemKind.Function, insertText: b })),
            ...ROBLOX_SERVICES.map(s => ({ label: s, kind: monaco.languages.CompletionItemKind.Class, insertText: s })),
            ...ROBLOX_METHODS.map(m => ({ label: m, kind: monaco.languages.CompletionItemKind.Method, insertText: m })),
        ];

        monaco.languages.registerCompletionItemProvider('luau', {
            provideCompletionItems: (model, position) => {
                const word = model.getWordUntilPosition(position);
                const range = {
                    startLineNumber: position.lineNumber,
                    endLineNumber: position.lineNumber,
                    startColumn: word.startColumn,
                    endColumn: word.endColumn
                };
                return {
                    suggestions: allCompletions.map(item => ({ ...item, range }))
                };
            }
        });

        editor = monaco.editor.create(document.getElementById('editor-container'), {
            value: 'print("fuck you nvidia")',
            language: 'luau',
            theme: 'luau-dark',
            fontSize: 14,
            fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            automaticLayout: true,
            tabSize: 4,
            wordWrap: 'on',
            lineNumbers: 'on',
            renderLineHighlight: 'line',
            cursorBlinking: 'smooth',
            smoothScrolling: true,
            suggestOnTriggerCharacters: true,
            quickSuggestions: true,
            acceptSuggestionOnEnter: 'on',
            padding: { top: 10 }
        });

        // Fix clipboard paste - support both Ctrl+V and Ctrl+Shift+V
        const pasteHandler = async () => {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    const selection = editor.getSelection();
                    const id = { major: 1, minor: 1 };
                    const op = { identifier: id, range: selection, text: text, forceMoveMarkers: true };
                    editor.executeEdits("clipboard", [op]);
                }
            } catch (err) {
                // Fallback: trigger Monaco's native paste
                document.execCommand('paste');
            }
        };

        // Register both keybindings
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyV, pasteHandler);
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyV, pasteHandler);

        editor.focus();
    });
}

function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('page-' + btn.dataset.page).classList.add('active');
            if (editor) editor.layout();
        });
    });
}

function initActions() {
    document.getElementById('btn-inject').addEventListener('click', async () => {
        const btn = document.getElementById('btn-inject');
        btn.textContent = '...';
        btn.disabled = true;
        log('Searching for Roblox process...', 'warning');

        try {
            const result = await invoke('inject_process');
            log(result, 'success');
            setConnected(true);
        } catch (err) {
            log('ERR: ' + err, 'error');
        }

        btn.textContent = 'INJECT';
        btn.disabled = false;
    });

    document.getElementById('btn-execute').addEventListener('click', async () => {
        if (!isConnected) {
            log('ERR: Not connected to process.', 'error');
            return;
        }

        const script = editor ? editor.getValue() : '';
        if (!script.trim()) return;

        log('Executing script...', 'warning');

        try {
            const result = await invoke('execute_script', { script });
            log(result, 'success');
        } catch (err) {
            log('ERR: ' + err, 'error');
        }
    });

    document.getElementById('btn-clear').addEventListener('click', () => {
        if (editor) editor.setValue('');
    });

    document.getElementById('btn-clear-console').addEventListener('click', () => {
        document.getElementById('console').innerHTML = '';
    });

    document.getElementById('btn-open').addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.lua,.txt';
        input.onchange = (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (ev) => {
                    if (editor) editor.setValue(ev.target.result);
                    log('Loaded: ' + file.name, 'success');
                };
                reader.readAsText(file);
            }
        };
        input.click();
    });

    document.getElementById('btn-save').addEventListener('click', () => {
        const content = editor ? editor.getValue() : '';
        const blob = new Blob([content], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'script.lua';
        a.click();
        log('Saved: script.lua', 'success');
    });
}

function initSettings() {
    document.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const isOn = btn.classList.toggle('on');
            btn.textContent = isOn ? '1' : '0';
        });
    });
}

function log(message, type = '') {
    const consoleEl = document.getElementById('console');
    const line = document.createElement('div');
    line.className = 'log-line ' + type;
    line.textContent = message;
    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setConnected(connected) {
    isConnected = connected;
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');

    if (connected) {
        dot.classList.add('connected');
        text.textContent = 'CONNECTED';
    } else {
        dot.classList.remove('connected');
        text.textContent = 'DISCONNECTED';
    }
}

async function startStatusCheck() {
    setInterval(async () => {
        try {
            const status = await invoke('check_status');
            if (status === 'connected' && !isConnected) {
                setConnected(true);
            }
        } catch (e) { }
    }, 2000);
}
