use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;

pub struct MemoryReader {
    pid: u32,
    mem_file: Option<File>,
}

impl MemoryReader {
    pub fn new(pid: u32) -> Result<Self, String> {
        let mem_path = format!("/proc/{}/mem", pid);
        let mem_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_RDONLY)
            .open(&mem_path)
            .map_err(|e| format!("Failed to open memory: {}", e))?;
        
        Ok(Self {
            pid,
            mem_file: Some(mem_file),
        })
    }

    pub fn read_bytes(&mut self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        let file = self.mem_file.as_mut().ok_or("Memory file not open")?;
        
        file.seek(SeekFrom::Start(address))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        let mut buffer = vec![0u8; size];
        file.read_exact(&mut buffer)
            .map_err(|e| format!("Read failed: {}", e))?;
        
        Ok(buffer)
    }

    pub fn read_u8(&mut self, address: u64) -> Result<u8, String> {
        let bytes = self.read_bytes(address, 1)?;
        Ok(bytes[0])
    }

    pub fn read_u16(&mut self, address: u64) -> Result<u16, String> {
        let bytes = self.read_bytes(address, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32(&mut self, address: u64) -> Result<u32, String> {
        let bytes = self.read_bytes(address, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64(&mut self, address: u64) -> Result<u64, String> {
        let bytes = self.read_bytes(address, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_i32(&mut self, address: u64) -> Result<i32, String> {
        let bytes = self.read_bytes(address, 4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_f32(&mut self, address: u64) -> Result<f32, String> {
        let bytes = self.read_bytes(address, 4)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_f64(&mut self, address: u64) -> Result<f64, String> {
        let bytes = self.read_bytes(address, 8)?;
        Ok(f64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_string(&mut self, address: u64, max_len: usize) -> Result<String, String> {
        let bytes = self.read_bytes(address, max_len)?;
        let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..null_pos].to_vec())
            .map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    pub fn read_pointer(&mut self, address: u64) -> Result<u64, String> {
        self.read_u64(address)
    }

    pub fn scan_pattern(&mut self, start: u64, end: u64, pattern: &[u8], mask: &[bool]) -> Vec<u64> {
        let mut results = Vec::new();
        let pattern_len = pattern.len();
        let chunk_size = 4096;
        
        let mut addr = start;
        while addr < end {
            let read_size = std::cmp::min(chunk_size, (end - addr) as usize);
            if let Ok(buffer) = self.read_bytes(addr, read_size) {
                for i in 0..buffer.len().saturating_sub(pattern_len) {
                    let mut matched = true;
                    for j in 0..pattern_len {
                        if mask[j] && buffer[i + j] != pattern[j] {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        results.push(addr + i as u64);
                    }
                }
            }
            addr += chunk_size as u64;
        }
        
        results
    }

    pub fn scan_value<T: PartialEq + Copy>(&mut self, start: u64, end: u64, value: T) -> Vec<u64> 
    where
        T: AsBytes,
    {
        let bytes = value.as_bytes();
        let mask = vec![true; bytes.len()];
        self.scan_pattern(start, end, &bytes, &mask)
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

impl AsBytes for u32 {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl AsBytes for u64 {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl AsBytes for i32 {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl AsBytes for f32 {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

pub struct MemoryWriter {
    pid: u32,
}

impl MemoryWriter {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }

    pub fn write_bytes(&self, address: u64, data: &[u8]) -> Result<(), String> {
        let mem_path = format!("/proc/{}/mem", self.pid);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&mem_path)
            .map_err(|e| format!("Failed to open memory for writing: {}", e))?;
        
        file.seek(SeekFrom::Start(address))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        file.write_all(data)
            .map_err(|e| format!("Write failed: {}", e))?;
        
        Ok(())
    }

    pub fn write_u8(&self, address: u64, value: u8) -> Result<(), String> {
        self.write_bytes(address, &[value])
    }

    pub fn write_u32(&self, address: u64, value: u32) -> Result<(), String> {
        self.write_bytes(address, &value.to_le_bytes())
    }

    pub fn write_u64(&self, address: u64, value: u64) -> Result<(), String> {
        self.write_bytes(address, &value.to_le_bytes())
    }

    pub fn write_f32(&self, address: u64, value: f32) -> Result<(), String> {
        self.write_bytes(address, &value.to_le_bytes())
    }

    pub fn nop(&self, address: u64, count: usize) -> Result<(), String> {
        let nops = vec![0x90u8; count];
        self.write_bytes(address, &nops)
    }

    pub fn patch_jump(&self, from: u64, to: u64) -> Result<(), String> {
        let offset = (to as i64 - from as i64 - 5) as i32;
        let mut patch = vec![0xE9u8];
        patch.extend_from_slice(&offset.to_le_bytes());
        self.write_bytes(from, &patch)
    }
}

pub fn dump_memory(pid: u32, start: u64, size: usize, output_path: &str) -> Result<(), String> {
    let mut reader = MemoryReader::new(pid)?;
    let data = reader.read_bytes(start, size)?;
    fs::write(output_path, data).map_err(|e| e.to_string())
}

pub fn search_string(pid: u32, start: u64, end: u64, needle: &str) -> Result<Vec<u64>, String> {
    let mut reader = MemoryReader::new(pid)?;
    let pattern = needle.as_bytes();
    let mask = vec![true; pattern.len()];
    Ok(reader.scan_pattern(start, end, pattern, &mask))
}
