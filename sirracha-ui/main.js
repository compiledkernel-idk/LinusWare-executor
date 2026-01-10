const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, execSync } = require('child_process');

let mainWindow;

// IPC paths
const IPC_READY_PATH = '/dev/shm/sirracha_ready';
const IPC_EXEC_PATH = '/dev/shm/sirracha_exec.txt';
const IPC_OUT_PATH = '/dev/shm/sirracha_output.txt';

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        minWidth: 900,
        minHeight: 600,
        frame: false,
        transparent: false,
        backgroundColor: '#0a0a0a',
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
        icon: path.join(__dirname, 'icon.png')
    });

    mainWindow.loadFile('index.html');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    app.quit();
});

// Find Sober PID
ipcMain.handle('find-sober', async () => {
    try {
        const result = execSync('pgrep -x sober | tail -1', { encoding: 'utf8' }).trim();
        return result ? parseInt(result) : null;
    } catch {
        return null;
    }
});

// Launch Sober
ipcMain.handle('launch-sober', async () => {
    try {
        spawn('flatpak', ['run', 'org.vinegarhq.Sober'], { detached: true, stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
});

// Inject into Sober
ipcMain.handle('inject', async (event, pid) => {
    try {
        const scriptPath = path.join(__dirname, '..', 'inject_sober.sh');
        const result = execSync(`pkexec ${scriptPath} ${pid}`, { encoding: 'utf8', timeout: 30000 });
        return { success: result.includes('SUCCESS'), output: result };
    } catch (e) {
        return { success: false, output: e.message };
    }
});

// Check ready signal
ipcMain.handle('check-ready', async (event, pid) => {
    try {
        const containerPath = `/proc/${pid}/root${IPC_READY_PATH}`;
        if (fs.existsSync(containerPath)) {
            return fs.readFileSync(containerPath, 'utf8');
        }
        if (fs.existsSync(IPC_READY_PATH)) {
            return fs.readFileSync(IPC_READY_PATH, 'utf8');
        }
        return null;
    } catch {
        return null;
    }
});

// Execute script
ipcMain.handle('execute-script', async (event, pid, script) => {
    try {
        const containerPath = `/proc/${pid}/root${IPC_EXEC_PATH}`;
        fs.writeFileSync(containerPath, script);

        // Wait for output
        await new Promise(r => setTimeout(r, 500));

        const outPath = `/proc/${pid}/root${IPC_OUT_PATH}`;
        if (fs.existsSync(outPath)) {
            const output = fs.readFileSync(outPath, 'utf8');
            fs.unlinkSync(outPath);
            return output;
        }
        return 'Script executed (no output)';
    } catch (e) {
        return `Error: ${e.message}`;
    }
});

// Window controls
ipcMain.on('minimize', () => mainWindow.minimize());
ipcMain.on('maximize', () => mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize());
ipcMain.on('close', () => mainWindow.close());
