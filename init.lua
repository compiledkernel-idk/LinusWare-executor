--[[ 
    Atingle init.lua
--]]

local getgenv = getgenv or function() return _G end
local env = getgenv()

env.getgenv         = getgenv
env.getrenv         = getrenv         or function() return game end
env.getreg          = getreg          or function() return debug.getregistry() end
env.getgc           = getgc           or function() return debug.getgc() end
env.getsenv         = getsenv         or function(_) return nil end
env.getfenv         = getfenv         or function(_) return nil end
env.setfenv         = setfenv         or function(_, _) end
env.getcallingscript= getcallingscript or function() return nil end

env.hookfunction    = hookfunction    or function(_, new) return new end
env.newcclosure     = newcclosure     or function(fn) return fn end
env.replaceclosure  = replaceclosure  or function(_, new) return new end

env.checkcaller     = checkcaller     or function() return false end
env.getupvalue      = debug.getupvalue    or function() end
env.setupvalue      = debug.setupvalue    or function() end
env.getinfo         = debug.getinfo       or function() end
env.getconstants    = debug.getconstants  or function() return {} end
env.getproto        = debug.getproto      or function() end
env.getprotos       = debug.getprotos     or function() return {} end
env.setconstant     = debug.setconstant   or function() end

env.mouse1click     = mouse1click     or function() end
env.mouse1press     = mouse1press     or function() end
env.mouse1release   = mouse1release   or function() end
env.mouse2click     = mouse2click     or function() end
env.mouse2press     = mouse2press     or function() end
env.mouse2release   = mouse2release   or function() end
env.mousemoverel    = mousemoverel    or function(_, _) end
env.mousemoveabs    = mousemoveabs    or function(_, _) end
env.keypress        = keypress        or function(_) end
env.keyrelease      = keyrelease      or function(_) end

local HttpService = game:GetService("HttpService")

env.http_get = function(url)
    local success, result = pcall(function()
        return HttpService:GetAsync(url)
    end)
    return success and result or nil
end

env.request = request or http_request or function(_)
    warn("[request] Not supported")
    return { StatusCode = 0, Body = "unsupported" }
end

env.setclipboard = setclipboard or function(text)
    warn("[setclipboard] Clipboard access not available")
end

env.protect_gui = protectgui or function(gui) return gui end

env.gethui = gethui or function()
    local core = game:GetService("CoreGui")
    for _, gui in ipairs(core:GetChildren()) do
        if gui:IsA("ScreenGui") then
            return gui
        end
    end
    return core
end

env.reverse_string = function(str)
    return str:reverse()
end

local Event = {}
Event.__index = Event

function Event.new()
    local self = setmetatable({}, Event)
    self._event = Instance.new("BindableEvent")
    return self
end

function Event:connect(callback)
    return self._event.Event:Connect(callback)
end

function Event:fire(...)
    self._event:Fire(...)
end

env.Event = Event
