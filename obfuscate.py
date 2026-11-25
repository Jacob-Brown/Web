import hashlib
import json
import secrets
import sys
import time

sys.path.insert(0, ".")

from source.pythonobf import Obfuscator as _Obfuscator


def clean_invite(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Discord invite is required.")
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if value.startswith("discord.gg/") or value.startswith("discord.com/invite/"):
        return "https://" + value
    if "discord.gg/" in value or "discord.com/invite/" in value:
        return value
    return "https://discord.gg/" + value.strip("/")


def invite_snippet(invite_url):
    return (
        "-- VoltageSec Discord invite\n"
        "task.spawn(function()\n"
        f'  local invite = "{invite_url}"\n'
        "  pcall(function()\n"
        "    if type(setclipboard) == 'function' then setclipboard(invite) end\n"
        "  end)\n"
        "  pcall(function()\n"
        "    local service = game:GetService('GuiService')\n"
        "    if type(service.OpenBrowserWindow) == 'function' then service:OpenBrowserWindow(invite) end\n"
        "  end)\n"
        "  pcall(function()\n"
        "    if type(request) == 'function' then request({Url = invite, Method = 'GET'}) end\n"
        "  end)\n"
        "  pcall(function()\n"
        "    if type(syn) == 'table' and type(syn.request) == 'function' then syn.request({Url = invite, Method = 'GET'}) end\n"
        "  end)\n"
        "  pcall(function()\n"
        "    if type(http) == 'table' and type(http.request) == 'function' then http.request({Url = invite, Method = 'GET'}) end\n"
        "  end)\n"
        "end)\n"
    )


def _lua_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def extract_invite_code(value: str) -> str:
    value = (value or "").strip()
    if "discord.gg/" in value or "discord.com/invite/" in value:
        value = value.rstrip("/").split("/")[-1]
    return value.split("?")[0].strip()


def discord_invite_input_snippet(invite: str) -> str:
    code = extract_invite_code(invite)
    return f"""local HttpService = game:GetService("HttpService")
local requestFunc = request or http_request or (syn and syn.request) or (fluxus and fluxus.request)

local function openDiscordInvite(inviteCode)
    inviteCode = inviteCode:gsub("https?://", ""):gsub("discord%.gg/", ""):gsub("discord%.com/invite/", "")

    local opened = false

    if requestFunc then
        local payload = HttpService:JSONEncode({{
            cmd = "INVITE_BROWSER",
            nonce = HttpService:GenerateGUID(false),
            args = {{
                code = inviteCode
            }}
        }})

        for port = 6463, 6472 do
            local success, response = pcall(function()
                return requestFunc({{
                    Url = string.format("http://127.0.0.1:%d/rpc?v=1", port),
                    Method = "POST",
                    Headers = {{
                        ["Content-Type"] = "application/json",
                        ["Origin"] = "https://discord.com"
                    }},
                    Body = payload
                }})
            end)

            if success and response and response.StatusCode == 200 then
                local data = HttpService:JSONDecode(response.Body)
                if data.evt ~= "ERROR" then
                    opened = true
                    break
                end
            end
        end
    end

    return opened
end

openDiscordInvite({_lua_string(code)})
"""


def main():
    request = json.load(sys.stdin)
    source = request.get("source") or ""
    preset = request.get("preset") or "maximum"
    seed = (request.get("seed") or "").strip()
    compression = request.get("compression")
    anti_tamper = request.get("anti_tamper")
    invite = request.get("discord_invite")
    inject = bool(request.get("inject_discord_invite"))

    if not source.strip():
        raise ValueError("Source is empty.")
    if len(source.encode("utf-8")) > int(request.get("max_source_bytes") or 200000):
        raise ValueError("Source is too large.")

    chosen_seed = seed if seed else str(secrets.randbits(32))
    if not chosen_seed.isdigit():
        raise ValueError("Seed must be a whole number.")

    presets = {
        "minimum", "medium", "compact", "balanced", "strong", "maximum",
        "all", "ultra", "auto", "debug", "hazma",
    }
    if preset not in presets:
        raise ValueError(f"Unknown preset: {preset}")

    original_source = source
    injected = False
    if inject and invite:
        source = discord_invite_input_snippet(invite) + "\n" + source
        injected = True

    started = time.perf_counter()
    result = _Obfuscator.obfuscate(
        source,
        preset=preset,
        seed=chosen_seed,
        compression=compression or None,
        anti_tamper=anti_tamper,
    )
    duration_ms = int((time.perf_counter() - started) * 1000)

    output = result.source.decode("utf-8", errors="replace")

    response = {
        "output": output,
        "input_bytes": len(original_source.encode("utf-8")),
        "output_bytes": len(output.encode("utf-8")),
        "duration_ms": duration_ms,
        "preset": preset,
        "seed": chosen_seed,
        "checksum": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "diagnostics": [str(item) for item in (result.diagnostics or [])][-30:],
        "discord_invite_injected": injected,
    }
    print(json.dumps(response))


if __name__ == "__main__":
    main()
