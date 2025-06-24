local getgenv = getgenv or function() return _G end
local getrenv = getrenv or function() return game end
local getreg = getreg or function() return debug.getregistry() end
local getgc = getgc or function() return debug.getgc() end
local getsenv = getsenv or function() return nil end
local getcallingscript = getcallingscript or function() return nil end

local env = getgenv()
env.getgenv = getgenv
env.getrenv = getrenv
env.getreg = getreg
env.getgc = getgc
env.getsenv = getsenv
env.getcallingscript = getcallingscript

function env.reverse_string(s: string): string
    return s:reverse()
end

local Event = {}
Event.__index = Event

function Event.new()
    local self = setmetatable({}, Event)
    self._event = Instance.new("BindableEvent")
    return self
end
function Event:connect(fn) return self._event.Event:Connect(fn) end
function Event:fire(...) self._event:Fire(...) end

env.Event = Event

local HttpService = game:GetService("HttpService")
function env.http_get(url: string): string?
    local ok, res = pcall(function()
        return HttpService:GetAsync(url)
    end)
    return ok and res or nil
end
