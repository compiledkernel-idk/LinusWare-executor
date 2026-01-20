use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

const SCRIPTS_DIR: &str = "scripts";
const HISTORY_FILE: &str = "script_history.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Script {
    pub name: String,
    pub content: String,
    pub category: ScriptCategory,
    pub description: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScriptCategory {
    Custom,
    Combat,
    Movement,
    Visual,
    Utility,
    Admin,
    Game,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionHistory {
    pub entries: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub script_name: String,
    pub content_preview: String,
    pub executed_at: u64,
    pub success: bool,
    pub output: Option<String>,
}

pub struct ScriptManager {
    base_path: PathBuf,
    scripts: HashMap<String, Script>,
    history: ExecutionHistory,
}

impl ScriptManager {
    pub fn new(base_path: &str) -> Result<Self, String> {
        let path = PathBuf::from(base_path).join(SCRIPTS_DIR);
        fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        
        let mut manager = Self {
            base_path: path,
            scripts: HashMap::new(),
            history: ExecutionHistory { entries: Vec::new() },
        };
        
        manager.load_scripts()?;
        manager.load_history()?;
        manager.load_builtin_scripts();
        
        Ok(manager)
    }

    fn load_builtin_scripts(&mut self) {
        let builtins = vec![
            ("Infinite Jump", "
local player = game.Players.LocalPlayer
local uis = game:GetService('UserInputService')

uis.JumpRequest:Connect(function()
    if player.Character and player.Character:FindFirstChild('Humanoid') then
        player.Character.Humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
    end
end)
print('Infinite Jump Enabled')", ScriptCategory::Movement),
            
            ("Speed Hack", "
local player = game.Players.LocalPlayer
local speed = 50

if player.Character and player.Character:FindFirstChild('Humanoid') then
    player.Character.Humanoid.WalkSpeed = speed
    print('Speed set to ' .. speed)
end", ScriptCategory::Movement),
            
            ("Fly Script", "
local player = game.Players.LocalPlayer
local flying = false
local speed = 50

local function fly()
    local char = player.Character
    if not char then return end
    local hrp = char:FindFirstChild('HumanoidRootPart')
    if not hrp then return end
    
    local bv = Instance.new('BodyVelocity')
    bv.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
    bv.Velocity = Vector3.new(0, 0, 0)
    bv.Parent = hrp
    
    local bg = Instance.new('BodyGyro')
    bg.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
    bg.P = 1000000
    bg.Parent = hrp
    
    flying = true
    print('Flying enabled - WASD to move, Space/Shift for up/down')
end

fly()", ScriptCategory::Movement),
            
            ("ESP Players", "
local players = game:GetService('Players')
local localPlayer = players.LocalPlayer

local function createESP(plr)
    if plr == localPlayer then return end
    
    local function addHighlight()
        local char = plr.Character
        if not char then return end
        
        local highlight = Instance.new('Highlight')
        highlight.FillColor = Color3.fromRGB(255, 0, 0)
        highlight.OutlineColor = Color3.fromRGB(255, 255, 255)
        highlight.FillTransparency = 0.5
        highlight.Parent = char
        
        local billboard = Instance.new('BillboardGui')
        billboard.Size = UDim2.new(0, 100, 0, 40)
        billboard.AlwaysOnTop = true
        billboard.Parent = char:WaitForChild('Head')
        
        local label = Instance.new('TextLabel')
        label.Size = UDim2.new(1, 0, 1, 0)
        label.BackgroundTransparency = 1
        label.TextColor3 = Color3.new(1, 1, 1)
        label.TextStrokeTransparency = 0
        label.Text = plr.Name
        label.Parent = billboard
    end
    
    plr.CharacterAdded:Connect(addHighlight)
    if plr.Character then addHighlight() end
end

for _, plr in pairs(players:GetPlayers()) do
    createESP(plr)
end
players.PlayerAdded:Connect(createESP)
print('ESP Enabled')", ScriptCategory::Visual),
            
            ("No Clip", "
local player = game.Players.LocalPlayer
local noclip = true

game:GetService('RunService').Stepped:Connect(function()
    if noclip and player.Character then
        for _, part in pairs(player.Character:GetDescendants()) do
            if part:IsA('BasePart') then
                part.CanCollide = false
            end
        end
    end
end)
print('NoClip Enabled')", ScriptCategory::Movement),
            
            ("Kill All", "
for _, v in pairs(game.Players:GetPlayers()) do
    if v ~= game.Players.LocalPlayer and v.Character then
        v.Character:BreakJoints()
    end
end
print('Attempted Kill All')", ScriptCategory::Combat),
            
            ("God Mode", "
local player = game.Players.LocalPlayer
local char = player.Character

if char then
    local humanoid = char:FindFirstChildOfClass('Humanoid')
    if humanoid then
        humanoid.MaxHealth = math.huge
        humanoid.Health = math.huge
        print('God Mode Enabled')
    end
end", ScriptCategory::Combat),
            
            ("Teleport Tool", "
local player = game.Players.LocalPlayer
local mouse = player:GetMouse()

mouse.Button1Down:Connect(function()
    if player.Character and player.Character:FindFirstChild('HumanoidRootPart') then
        player.Character.HumanoidRootPart.CFrame = CFrame.new(mouse.Hit.Position + Vector3.new(0, 3, 0))
    end
end)
print('Click to teleport')", ScriptCategory::Utility),
            
            ("Print LocalPlayer Info", "
local player = game.Players.LocalPlayer
print('=== Player Info ===')
print('Name:', player.Name)
print('DisplayName:', player.DisplayName)
print('UserId:', player.UserId)
print('AccountAge:', player.AccountAge)
if player.Character then
    local humanoid = player.Character:FindFirstChildOfClass('Humanoid')
    if humanoid then
        print('Health:', humanoid.Health, '/', humanoid.MaxHealth)
        print('WalkSpeed:', humanoid.WalkSpeed)
        print('JumpPower:', humanoid.JumpPower)
    end
    local hrp = player.Character:FindFirstChild('HumanoidRootPart')
    if hrp then
        print('Position:', hrp.Position)
    end
end
print('===================')", ScriptCategory::Utility),
            
            ("Get Game Info", "
print('=== Game Info ===')
print('PlaceId:', game.PlaceId)
print('PlaceVersion:', game.PlaceVersion)
print('JobId:', game.JobId)
print('Players:', #game.Players:GetPlayers())
print('Workspace Children:', #workspace:GetChildren())
print('==================')", ScriptCategory::Utility),
        ];
        
        for (name, content, category) in builtins {
            if !self.scripts.contains_key(name) {
                self.scripts.insert(name.to_string(), Script {
                    name: name.to_string(),
                    content: content.trim().to_string(),
                    category,
                    description: String::new(),
                    created_at: 0,
                    modified_at: 0,
                    favorite: false,
                });
            }
        }
    }

    pub fn load_scripts(&mut self) -> Result<(), String> {
        if !self.base_path.exists() {
            return Ok(());
        }
        
        for entry in fs::read_dir(&self.base_path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            
            if path.extension().map_or(false, |e| e == "lua" || e == "json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    let name = path.file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    
                    if path.extension().map_or(false, |e| e == "json") {
                        if let Ok(script) = serde_json::from_str::<Script>(&content) {
                            self.scripts.insert(script.name.clone(), script);
                        }
                    } else {
                        self.scripts.insert(name.clone(), Script {
                            name,
                            content,
                            category: ScriptCategory::Custom,
                            description: String::new(),
                            created_at: 0,
                            modified_at: 0,
                            favorite: false,
                        });
                    }
                }
            }
        }
        
        Ok(())
    }

    fn load_history(&mut self) -> Result<(), String> {
        let path = self.base_path.join(HISTORY_FILE);
        if path.exists() {
            let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            self.history = serde_json::from_str(&content).unwrap_or(ExecutionHistory { entries: Vec::new() });
        }
        Ok(())
    }

    fn save_history(&self) -> Result<(), String> {
        let path = self.base_path.join(HISTORY_FILE);
        let content = serde_json::to_string_pretty(&self.history).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())
    }

    pub fn save_script(&mut self, script: Script) -> Result<(), String> {
        let path = self.base_path.join(format!("{}.json", &script.name));
        let content = serde_json::to_string_pretty(&script).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())?;
        self.scripts.insert(script.name.clone(), script);
        Ok(())
    }

    pub fn delete_script(&mut self, name: &str) -> Result<(), String> {
        let path = self.base_path.join(format!("{}.json", name));
        if path.exists() {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        let lua_path = self.base_path.join(format!("{}.lua", name));
        if lua_path.exists() {
            fs::remove_file(lua_path).map_err(|e| e.to_string())?;
        }
        self.scripts.remove(name);
        Ok(())
    }

    pub fn get_script(&self, name: &str) -> Option<&Script> {
        self.scripts.get(name)
    }

    pub fn get_all_scripts(&self) -> Vec<&Script> {
        self.scripts.values().collect()
    }

    pub fn get_scripts_by_category(&self, category: ScriptCategory) -> Vec<&Script> {
        self.scripts.values().filter(|s| s.category == category).collect()
    }

    pub fn get_favorites(&self) -> Vec<&Script> {
        self.scripts.values().filter(|s| s.favorite).collect()
    }

    pub fn search(&self, query: &str) -> Vec<&Script> {
        let query_lower = query.to_lowercase();
        self.scripts.values()
            .filter(|s| {
                s.name.to_lowercase().contains(&query_lower) ||
                s.content.to_lowercase().contains(&query_lower) ||
                s.description.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    pub fn add_to_history(&mut self, name: &str, content: &str, success: bool, output: Option<String>) {
        let entry = HistoryEntry {
            script_name: name.to_string(),
            content_preview: content.chars().take(100).collect(),
            executed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            success,
            output,
        };
        
        self.history.entries.push(entry);
        if self.history.entries.len() > 100 {
            self.history.entries.remove(0);
        }
        
        self.save_history().ok();
    }

    pub fn get_history(&self) -> &[HistoryEntry] {
        &self.history.entries
    }

    pub fn clear_history(&mut self) {
        self.history.entries.clear();
        self.save_history().ok();
    }

    pub fn validate_lua_syntax(&self, code: &str) -> Result<(), Vec<LuaSyntaxError>> {
        let mut errors = Vec::new();
        let mut depth = 0;
        let mut in_string = false;
        let mut string_char = ' ';
        
        for (line_num, line) in code.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();
            
            if trimmed.starts_with("--") {
                continue;
            }
            
            let mut chars = trimmed.chars().peekable();
            while let Some(c) = chars.next() {
                if in_string {
                    if c == string_char && chars.peek() != Some(&'\\') {
                        in_string = false;
                    }
                } else {
                    match c {
                        '"' | '\'' => {
                            in_string = true;
                            string_char = c;
                        }
                        _ => {}
                    }
                }
            }
            
            if !in_string {
                let keywords_open = ["function", "if", "for", "while", "repeat", "do"];
                let keywords_close = ["end"];
                let keywords_middle = ["then", "else", "elseif"];
                
                for kw in keywords_open {
                    if trimmed.contains(kw) {
                        depth += 1;
                    }
                }
                for kw in keywords_close {
                    if trimmed.contains(kw) {
                        depth -= 1;
                    }
                }
            }
        }
        
        if depth > 0 {
            errors.push(LuaSyntaxError {
                line: code.lines().count(),
                message: format!("Missing {} 'end' statement(s)", depth),
            });
        } else if depth < 0 {
            errors.push(LuaSyntaxError {
                line: 1,
                message: format!("Extra {} 'end' statement(s)", -depth),
            });
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug)]
pub struct LuaSyntaxError {
    pub line: usize,
    pub message: String,
}

impl Default for ScriptManager {
    fn default() -> Self {
        Self::new(".").unwrap()
    }
}
