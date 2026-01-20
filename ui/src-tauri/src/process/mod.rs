mod scanner;

pub use scanner::*;

use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

pub struct ProcessManager {
    scanner: ProcessScanner,
    attached_pid: Option<u32>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            scanner: ProcessScanner::new(),
            attached_pid: None,
        }
    }

    pub fn attach(&mut self, pid: u32) -> Result<(), String> {
        if !self.scanner.is_running(pid) {
            return Err(format!("Process {} not found", pid));
        }
        self.attached_pid = Some(pid);
        Ok(())
    }

    pub fn detach(&mut self) {
        self.attached_pid = None;
    }

    pub fn get_attached(&self) -> Option<u32> {
        self.attached_pid
    }

    pub fn find_and_attach_roblox(&mut self) -> Result<u32, String> {
        let proc = self.scanner.find_roblox()
            .ok_or("Roblox process not found")?;
        self.attach(proc.pid)?;
        Ok(proc.pid)
    }

    pub fn get_process_info(&mut self, pid: u32) -> Option<ProcessInfo> {
        self.scanner.refresh();
        self.scanner.find_by_name(&pid.to_string())
    }

    pub fn get_memory_regions(&self) -> Vec<MemoryRegion> {
        if let Some(pid) = self.attached_pid {
            self.scanner.find_executable_regions(pid)
        } else {
            Vec::new()
        }
    }

    pub fn get_base_address(&self) -> Option<u64> {
        self.attached_pid.and_then(|pid| self.scanner.get_base_address(pid))
    }

    pub fn is_attached(&self) -> bool {
        if let Some(pid) = self.attached_pid {
            self.scanner.is_running(pid)
        } else {
            false
        }
    }

    pub fn kill_process(&self, pid: u32) -> Result<(), String> {
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn suspend_process(&self, pid: u32) -> Result<(), String> {
        Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .output()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn resume_process(&self, pid: u32) -> Result<(), String> {
        Command::new("kill")
            .args(["-CONT", &pid.to_string()])
            .output()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn watch_process<F>(&self, pid: u32, callback: F) -> Result<(), String>
    where
        F: Fn(&str) + Send + 'static,
    {
        let strace = Command::new("strace")
            .args(["-p", &pid.to_string(), "-e", "trace=write"])
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        
        if let Some(stderr) = strace.stderr {
            let reader = BufReader::new(stderr);
            for line in reader.lines().flatten() {
                callback(&line);
            }
        }
        Ok(())
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn find_game_process() -> Option<u32> {
    let mut manager = ProcessManager::new();
    manager.find_and_attach_roblox().ok()
}
