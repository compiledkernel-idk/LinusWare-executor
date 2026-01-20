use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

const IPC_DIR: &str = "/tmp/linusware";
const SCRIPT_FILE: &str = "script.lua";
const OUTPUT_FILE: &str = "output.txt";
const READY_FILE: &str = "ready";
const COMMAND_FILE: &str = "command";

pub struct IpcChannel {
    base_path: PathBuf,
    message_queue: Arc<Mutex<VecDeque<IpcMessage>>>,
}

#[derive(Debug, Clone)]
pub enum IpcMessage {
    Script(String),
    Command(String),
    Output(String),
    Status(ConnectionStatus),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl IpcChannel {
    pub fn new() -> Result<Self, String> {
        let base_path = PathBuf::from(IPC_DIR);
        fs::create_dir_all(&base_path).map_err(|e| e.to_string())?;
        
        Ok(Self {
            base_path,
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    pub fn send_script(&self, script: &str) -> Result<(), String> {
        let path = self.base_path.join(SCRIPT_FILE);
        fs::write(&path, script).map_err(|e| e.to_string())?;
        self.queue_message(IpcMessage::Script(script.to_string()));
        Ok(())
    }

    pub fn send_command(&self, command: &str) -> Result<(), String> {
        let path = self.base_path.join(COMMAND_FILE);
        fs::write(&path, command).map_err(|e| e.to_string())?;
        self.queue_message(IpcMessage::Command(command.to_string()));
        Ok(())
    }

    pub fn read_output(&self) -> Result<String, String> {
        let path = self.base_path.join(OUTPUT_FILE);
        if path.exists() {
            let output = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            fs::remove_file(&path).ok();
            Ok(output)
        } else {
            Ok(String::new())
        }
    }

    pub fn check_ready(&self) -> bool {
        self.base_path.join(READY_FILE).exists()
    }

    pub fn set_ready(&self) -> Result<(), String> {
        let path = self.base_path.join(READY_FILE);
        File::create(&path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn clear_ready(&self) -> Result<(), String> {
        let path = self.base_path.join(READY_FILE);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn get_status(&self) -> ConnectionStatus {
        if self.check_ready() {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        }
    }

    fn queue_message(&self, msg: IpcMessage) {
        if let Ok(mut queue) = self.message_queue.lock() {
            queue.push_back(msg);
            if queue.len() > 100 {
                queue.pop_front();
            }
        }
    }

    pub fn poll_messages(&self) -> Vec<IpcMessage> {
        if let Ok(mut queue) = self.message_queue.lock() {
            queue.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    pub fn cleanup(&self) -> Result<(), String> {
        if self.base_path.exists() {
            for entry in fs::read_dir(&self.base_path).map_err(|e| e.to_string())? {
                if let Ok(entry) = entry {
                    fs::remove_file(entry.path()).ok();
                }
            }
        }
        Ok(())
    }
}

impl Default for IpcChannel {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl Drop for IpcChannel {
    fn drop(&mut self) {
        self.cleanup().ok();
    }
}

pub struct SharedMemory {
    name: String,
    size: usize,
    fd: i32,
    ptr: *mut u8,
}

impl SharedMemory {
    pub fn create(name: &str, size: usize) -> Result<Self, String> {
        use std::ffi::CString;
        
        let shm_name = CString::new(format!("/{}", name))
            .map_err(|e| e.to_string())?;
        
        let fd = unsafe {
            libc::shm_open(
                shm_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR,
                0o666,
            )
        };
        
        if fd < 0 {
            return Err("Failed to create shared memory".to_string());
        }
        
        if unsafe { libc::ftruncate(fd, size as i64) } < 0 {
            unsafe { libc::close(fd) };
            return Err("Failed to set shared memory size".to_string());
        }
        
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        
        if ptr == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err("Failed to map shared memory".to_string());
        }
        
        Ok(Self {
            name: name.to_string(),
            size,
            fd,
            ptr: ptr as *mut u8,
        })
    }

    pub fn write(&self, offset: usize, data: &[u8]) -> Result<(), String> {
        if offset + data.len() > self.size {
            return Err("Write exceeds shared memory bounds".to_string());
        }
        
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.ptr.add(offset),
                data.len(),
            );
        }
        
        Ok(())
    }

    pub fn read(&self, offset: usize, len: usize) -> Result<Vec<u8>, String> {
        if offset + len > self.size {
            return Err("Read exceeds shared memory bounds".to_string());
        }
        
        let mut buffer = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.ptr.add(offset),
                buffer.as_mut_ptr(),
                len,
            );
        }
        
        Ok(buffer)
    }

    pub fn write_string(&self, offset: usize, s: &str) -> Result<(), String> {
        let bytes = s.as_bytes();
        let mut data = (bytes.len() as u32).to_le_bytes().to_vec();
        data.extend_from_slice(bytes);
        self.write(offset, &data)
    }

    pub fn read_string(&self, offset: usize) -> Result<String, String> {
        let len_bytes = self.read(offset, 4)?;
        let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        let string_bytes = self.read(offset + 4, len)?;
        String::from_utf8(string_bytes).map_err(|e| e.to_string())
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
            libc::close(self.fd);
            let shm_name = std::ffi::CString::new(format!("/{}", self.name)).unwrap();
            libc::shm_unlink(shm_name.as_ptr());
        }
    }
}
