"""In-process VoltageSec obfuscator API used by the Discord bot.

Usage:
    from source.pythonobf import Obfuscator
    result = Obfuscator.obfuscate(source, preset="compact", seed=42)
    lua = result.source  # bytes, already includes the protection banner
"""

from __future__ import annotations

from . import voltage

__all__ = ["obfuscate", "compile", "Config", "Error", "Result", "PRESETS"]

PRESETS = (
    "minimum",
    "medium",
    "compact",
    "balanced",
    "strong",
    "maximum",
    "all",
    "ultra",
    "auto",
    "debug",
    "hazma",
)

# Presets that get the full protection stack, matching the bot's old CLI flags:
# --anti-tamper --hardening 5 --vm-noise 5 --operand-encoding mixed
# --vm-layout permuted --vm-dispatch indirect
_FULL_STACK_PRESETS = frozenset({"all", "maximum", "ultra"})

# Presets that enable the complete V2 protection stack. The compiler also
# enforces this hardened baseline, but setting it here keeps explicit configs
# and diagnostics consistent for every shipping profile.
_V2_PRESETS = frozenset(p for p in PRESETS if p not in {"debug", "minimum"})

Config = voltage.Config
Error = voltage.Error
Result = voltage.Result
compile = voltage.compile


def obfuscate(
    source: str | bytes,
    *,
    preset: str = "compact",
    seed: int | str | None = None,
    anti_tamper: bool | None = None,
    max_source: int | None = None,
    compression: str | None = None,
    extra: dict | None = None,
) -> Result:
    """Obfuscate Lua/Luau source entirely in-process.

    Args:
        source: Lua source as text or UTF-8 bytes.
        preset: One of PRESETS.
        seed: Numeric seed; when omitted the C++ CLI derived one from
            time/pid. We keep that behaviour by leaving it out of the config.
        anti_tamper: Override the preset-derived anti-tamper flag.
        max_source: Compiler read budget. Defaults to the exact input size,
            matching the old bot adapter's `maxSource` config.json.
        compression: Explicit compression pipeline (e.g. "delta+lzma").
            When omitted, the obfuscator's measured "auto" resolver picks one.
        extra: Additional raw config keys for advanced callers.

    Returns:
        voltage.Result with `.source` (bytes), `.metadata` and `.diagnostics`.

    Raises:
        ValueError: for an unknown preset or a non-numeric seed.
        voltage.Error: for compiler failures.
    """
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset: {preset}")

    if isinstance(source, str):
        source_bytes = source.encode("utf-8")
    else:
        source_bytes = bytes(source)

    cfg: dict = {
        "maxSource": max_source if max_source is not None else len(source_bytes),
        "preset": preset,
        # antiTamperExplicit matters: Config.fromJson treats the key's presence
        # as an explicit override, so always include it.
        "antiTamper": preset in _FULL_STACK_PRESETS
        if anti_tamper is None
        else bool(anti_tamper),
    }

    if preset in _FULL_STACK_PRESETS:
        cfg.update(
            {
                "hardening": 5,
                "vmNoise": 5,
                "operandEncoding": "mixed",
                "vmLayout": "permuted",
                "vmDispatch": "indirect",
            }
        )

    if preset in _V2_PRESETS:
        from .v2 import V2_FEATURES

        cfg["v2"] = True
        cfg["v2Features"] = list(V2_FEATURES)

    if seed is not None:
        text = str(seed)
        if not text.isdigit():
            raise ValueError("Seed must be a whole number.")
        cfg["seed"] = int(text)

    if compression is not None:
        cfg["compression"] = compression
        cfg["compressionExplicit"] = True

    if extra:
        cfg.update(extra)

    config = voltage.Config.fromJson(cfg)
    return voltage.compile(source_bytes, config)
