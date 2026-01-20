use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

const CONFIG_FILE: &str = "linusware.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub injection: InjectionConfig,
    pub editor: EditorConfig,
    pub theme: ThemeConfig,
    pub keybinds: KeybindConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub auto_inject: bool,
    pub auto_execute: bool,
    pub always_on_top: bool,
    pub minimize_to_tray: bool,
    pub check_updates: bool,
    pub telemetry: bool,
    pub last_script: Option<String>,
    pub window_x: Option<i32>,
    pub window_y: Option<i32>,
    pub window_width: u32,
    pub window_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    pub method: InjectionMethod,
    pub retry_count: u32,
    pub retry_delay_ms: u32,
    pub auto_reattach: bool,
    pub process_name: String,
    pub library_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionMethod {
    Ptrace,
    DlOpen,
    LdPreload,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorConfig {
    pub font_family: String,
    pub font_size: u32,
    pub tab_size: u32,
    pub word_wrap: bool,
    pub line_numbers: bool,
    pub minimap: bool,
    pub auto_complete: bool,
    pub bracket_matching: bool,
    pub highlight_line: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeConfig {
    pub name: String,
    pub background: String,
    pub foreground: String,
    pub accent: String,
    pub sidebar: String,
    pub editor_bg: String,
    pub line_highlight: String,
    pub selection: String,
    pub keyword_color: String,
    pub string_color: String,
    pub comment_color: String,
    pub number_color: String,
    pub function_color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeybindConfig {
    pub execute: String,
    pub inject: String,
    pub clear: String,
    pub save: String,
    pub open: String,
    pub toggle_console: String,
    pub toggle_settings: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                auto_inject: false,
                auto_execute: false,
                always_on_top: false,
                minimize_to_tray: false,
                check_updates: true,
                telemetry: false,
                last_script: None,
                window_x: None,
                window_y: None,
                window_width: 1100,
                window_height: 720,
            },
            injection: InjectionConfig {
                method: InjectionMethod::Ptrace,
                retry_count: 3,
                retry_delay_ms: 500,
                auto_reattach: true,
                process_name: "RobloxPlayer".to_string(),
                library_path: "./linusware.so".to_string(),
            },
            editor: EditorConfig {
                font_family: "JetBrains Mono".to_string(),
                font_size: 14,
                tab_size: 4,
                word_wrap: true,
                line_numbers: true,
                minimap: false,
                auto_complete: true,
                bracket_matching: true,
                highlight_line: true,
            },
            theme: ThemeConfig::dark(),
            keybinds: KeybindConfig {
                execute: "F5".to_string(),
                inject: "F1".to_string(),
                clear: "Ctrl+L".to_string(),
                save: "Ctrl+S".to_string(),
                open: "Ctrl+O".to_string(),
                toggle_console: "F2".to_string(),
                toggle_settings: "F3".to_string(),
            },
        }
    }
}

impl ThemeConfig {
    pub fn dark() -> Self {
        Self {
            name: "Dark".to_string(),
            background: "#121212".to_string(),
            foreground: "#e0e0e0".to_string(),
            accent: "#ffffff".to_string(),
            sidebar: "#1a1a1a".to_string(),
            editor_bg: "#0a0a0a".to_string(),
            line_highlight: "#1a1a1a".to_string(),
            selection: "#264f78".to_string(),
            keyword_color: "#c586c0".to_string(),
            string_color: "#ce9178".to_string(),
            comment_color: "#6a9955".to_string(),
            number_color: "#b5cea8".to_string(),
            function_color: "#dcdcaa".to_string(),
        }
    }

    pub fn light() -> Self {
        Self {
            name: "Light".to_string(),
            background: "#ffffff".to_string(),
            foreground: "#333333".to_string(),
            accent: "#0066cc".to_string(),
            sidebar: "#f5f5f5".to_string(),
            editor_bg: "#ffffff".to_string(),
            line_highlight: "#f0f0f0".to_string(),
            selection: "#add6ff".to_string(),
            keyword_color: "#0000ff".to_string(),
            string_color: "#a31515".to_string(),
            comment_color: "#008000".to_string(),
            number_color: "#098658".to_string(),
            function_color: "#795e26".to_string(),
        }
    }

    pub fn hacker() -> Self {
        Self {
            name: "Hacker".to_string(),
            background: "#000000".to_string(),
            foreground: "#00ff00".to_string(),
            accent: "#00ff00".to_string(),
            sidebar: "#0a0a0a".to_string(),
            editor_bg: "#000000".to_string(),
            line_highlight: "#001100".to_string(),
            selection: "#003300".to_string(),
            keyword_color: "#00ff00".to_string(),
            string_color: "#00cc00".to_string(),
            comment_color: "#006600".to_string(),
            number_color: "#00ff66".to_string(),
            function_color: "#66ff66".to_string(),
        }
    }

    pub fn purple() -> Self {
        Self {
            name: "Purple".to_string(),
            background: "#1a1a2e".to_string(),
            foreground: "#eaeaea".to_string(),
            accent: "#9b59b6".to_string(),
            sidebar: "#16213e".to_string(),
            editor_bg: "#0f0f1a".to_string(),
            line_highlight: "#1f1f3a".to_string(),
            selection: "#3d3d6b".to_string(),
            keyword_color: "#9b59b6".to_string(),
            string_color: "#e74c3c".to_string(),
            comment_color: "#7f8c8d".to_string(),
            number_color: "#2ecc71".to_string(),
            function_color: "#f39c12".to_string(),
        }
    }
}

pub struct ConfigManager {
    config_path: PathBuf,
    pub config: Config,
}

impl ConfigManager {
    pub fn new(base_path: &str) -> Result<Self, String> {
        let config_path = PathBuf::from(base_path).join(CONFIG_FILE);
        let config = if config_path.exists() {
            let content = fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Config::default()
        };
        
        let mut manager = Self { config_path, config };
        manager.save()?;
        
        Ok(manager)
    }

    pub fn save(&self) -> Result<(), String> {
        let content = serde_json::to_string_pretty(&self.config).map_err(|e| e.to_string())?;
        fs::write(&self.config_path, content).map_err(|e| e.to_string())
    }

    pub fn reload(&mut self) -> Result<(), String> {
        if self.config_path.exists() {
            let content = fs::read_to_string(&self.config_path).map_err(|e| e.to_string())?;
            self.config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), String> {
        self.config = Config::default();
        self.save()
    }

    pub fn set_theme(&mut self, theme: ThemeConfig) -> Result<(), String> {
        self.config.theme = theme;
        self.save()
    }

    pub fn get_theme(&self) -> &ThemeConfig {
        &self.config.theme
    }

    pub fn set_auto_inject(&mut self, value: bool) -> Result<(), String> {
        self.config.general.auto_inject = value;
        self.save()
    }

    pub fn set_auto_execute(&mut self, value: bool) -> Result<(), String> {
        self.config.general.auto_execute = value;
        self.save()
    }

    pub fn set_always_on_top(&mut self, value: bool) -> Result<(), String> {
        self.config.general.always_on_top = value;
        self.save()
    }

    pub fn set_process_name(&mut self, name: &str) -> Result<(), String> {
        self.config.injection.process_name = name.to_string();
        self.save()
    }

    pub fn save_window_state(&mut self, x: i32, y: i32, w: u32, h: u32) -> Result<(), String> {
        self.config.general.window_x = Some(x);
        self.config.general.window_y = Some(y);
        self.config.general.window_width = w;
        self.config.general.window_height = h;
        self.save()
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new(".").unwrap()
    }
}
