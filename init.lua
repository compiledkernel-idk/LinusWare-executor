# Why? will impliment in c later


local getgenv = getgenv or function() return _G end
local env = getgenv()

env.getgenv = getgenv
env.getrenv = getrenv or function() return game end
env.getreg = getreg or function() return debug.getregistry() end
env.getgc = getgc or function() return debug.getgc() end
env.getsenv = getsenv or function(scr) return nil end
env.getfenv = getfenv or function(fn) return nil end
env.setfenv = setfenv or function(fn, tbl) end
env.getcallingscript = getcallingscript or function() return nil end
env.hookfunction = hookfunction or function(func, new) return new end
env.newcclosure = newcclosure or function(f) return f end
env.replaceclosure = replaceclosure or function(f, new) return new end
env.checkcaller = checkcaller or function() return false end
env.getupvalue = debug.getupvalue or function() end
env.setupvalue = debug.setupvalue or function() end
env.getinfo = debug.getinfo or function() end
env.getconstants = debug.getconstants or function() return {} end
env.getproto = debug.getproto or function() end
env.getprotos = debug.getprotos or function() return {} end
env.setconstant = debug.setconstant or function() end
env.mouse1click = mouse1click or function() end
env.mouse1press = mouse1press or function() end
env.mouse1release = mouse1release or function() end
env.mouse2click = mouse2click or function() end
env.mouse2press = mouse2press or function() end
env.mouse2release = mouse2release or function() end
env.mousemoverel = mousemoverel or function(x, y) end
env.mousemoveabs = mousemoveabs or function(x, y) end
env.keypress = keypress or function(k) end
env.keyrelease = keyrelease or function(k) end

local HttpService = game:GetService("HttpService")

env.http_get = function(url)
    local ok, res = pcall(function()
        return HttpService:GetAsync(url)
    end)
    return ok and res or nil
end

env.request = request or http_request or function(tbl)
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
        if gui:IsA("ScreenGui") then return gui end
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

function Event:connect(fn)
    return self._event.Event:Connect(fn)
end

function Event:fire(...)
    self._event:Fire(...)
end

env.Event = Event
