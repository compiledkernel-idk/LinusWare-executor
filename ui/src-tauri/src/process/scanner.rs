use std::fs;
use std::path::Path;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: String,
    pub memory_maps: Vec<MemoryRegion>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub path: Option<String>,
}

pub struct ProcessScanner {
    cache: HashMap<u32, ProcessInfo>,
}

impl ProcessScanner {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn find_by_name(&mut self, name: &str) -> Option<ProcessInfo> {
        self.refresh();
        self.cache.values().find(|p| p.name.contains(name)).cloned()
    }

    pub fn find_roblox(&mut self) -> Option<ProcessInfo> {
        let targets = ["RobloxPlayer", "Roblox", "sober", "wine-preloader"];
        for target in targets {
            if let Some(proc) = self.find_by_name(target) {
                return Some(proc);
            }
        }
        None
    }

    pub fn get_all(&mut self) -> Vec<ProcessInfo> {
        self.refresh();
        self.cache.values().cloned().collect()
    }

    pub fn refresh(&mut self) {
        self.cache.clear();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    if let Some(info) = self.read_process_info(pid) {
                        self.cache.insert(pid, info);
                    }
                }
            }
        }
    }

    fn read_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);
        
        let name = fs::read_to_string(format!("{}/comm", proc_path))
            .ok()?
            .trim()
            .to_string();
        
        let cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();
        
        let exe_path = fs::read_link(format!("{}/exe", proc_path))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        
        let memory_maps = self.parse_maps(pid);
        
        Some(ProcessInfo {
            pid,
            name,
            cmdline,
            exe_path,
            memory_maps,
        })
    }

    fn parse_maps(&self, pid: u32) -> Vec<MemoryRegion> {
        let maps_path = format!("/proc/{}/maps", pid);
        let content = match fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        
        content.lines().filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return None;
            }
            
            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() != 2 {
                return None;
            }
            
            let start = u64::from_str_radix(addr_parts[0], 16).ok()?;
            let end = u64::from_str_radix(addr_parts[1], 16).ok()?;
            let permissions = parts[1].to_string();
            let path = parts.get(5).map(|s| s.to_string());
            
            Some(MemoryRegion {
                start,
                end,
                permissions,
                path,
            })
        }).collect()
    }

    pub fn find_executable_regions(&self, pid: u32) -> Vec<MemoryRegion> {
        if let Some(info) = self.cache.get(&pid) {
            info.memory_maps.iter()
                .filter(|r| r.permissions.contains('x'))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn find_writable_regions(&self, pid: u32) -> Vec<MemoryRegion> {
        if let Some(info) = self.cache.get(&pid) {
            info.memory_maps.iter()
                .filter(|r| r.permissions.contains('w'))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_base_address(&self, pid: u32) -> Option<u64> {
        self.cache.get(&pid)?
            .memory_maps
            .iter()
            .filter(|r| r.permissions.contains('x'))
            .map(|r| r.start)
            .min()
    }

    pub fn is_running(&self, pid: u32) -> bool {
        Path::new(&format!("/proc/{}", pid)).exists()
    }
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_pid_by_name(name: &str) -> Option<u32> {
    let mut scanner = ProcessScanner::new();
    scanner.find_by_name(name).map(|p| p.pid)
}

pub fn list_processes() -> Vec<(u32, String)> {
    let mut scanner = ProcessScanner::new();
    scanner.get_all().iter().map(|p| (p.pid, p.name.clone())).collect()
}
