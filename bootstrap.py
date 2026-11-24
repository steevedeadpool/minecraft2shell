import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path


VERSION = "26.3"
CLIENT_SHA256 = "4508d006323f24fa02876310c192d739af56516eb259000ac50f0909a68c9a2d"
FREETYPE_SHA256 = "fcac5b5a9a8977f1bc76eccea5e71f6c57250ca5ab8605f06906377e91b6e6b7"
VERSION_INDEX_URL = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
JAVA_INDEX_URL = "https://piston-meta.mojang.com/v1/products/java-runtime/2ec0cc96c44e5a76b9c8b7c39df7210883d12871/all.json"


def digest(path, name):
    h = hashlib.new(name)
    with Path(path).open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def official_file(url, destination, sha1=None, size=None):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        size_ok = size is None or destination.stat().st_size == int(size)
        hash_ok = sha1 is None or digest(destination, "sha1").lower() == sha1.lower()
        if size_ok and hash_ok:
            return destination
    temporary = destination.with_name(destination.name + ".download")
    last_error = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Minecraft-Resource-Pack-PoC/1"})
            with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output, 1024 * 1024)
            if size is not None and temporary.stat().st_size != int(size):
                raise RuntimeError(f"Downloaded size mismatch for {url}")
            if sha1 is not None and digest(temporary, "sha1").lower() != sha1.lower():
                raise RuntimeError(f"Downloaded checksum mismatch for {url}")
            temporary.replace(destination)
            return destination
        except Exception as error:
            last_error = error
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError(f"Could not download {url}: {last_error}")


def nbt_string(value):
    encoded = value.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def trusted_servers_file(path):
    result = bytearray(b"\x0a\x00\x00")
    result += b"\x09" + nbt_string("servers") + b"\x0a" + struct.pack(">I", 1)
    result += b"\x01" + nbt_string("hidden") + b"\x01"
    result += b"\x08" + nbt_string("ip") + nbt_string("127.0.0.1:25565")
    result += b"\x08" + nbt_string("name") + nbt_string("Minecraft Server")
    result += b"\x01" + nbt_string("acceptTextures") + b"\x01"
    result += b"\x00\x00"
    Path(path).write_bytes(result)


def java_version_matches(path):
    path = Path(path)
    if not path.is_file():
        return False
    try:
        process = subprocess.run([str(path), "-version"], capture_output=True, text=True, timeout=15)
        return 'version "25.0.1' in (process.stdout + process.stderr)
    except (OSError, subprocess.TimeoutExpired):
        return False


def java_candidates():
    candidates = []
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]) / "bin" / "java.exe")
    command = shutil.which("java.exe")
    if command:
        candidates.append(Path(command))
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    candidates.append(appdata / ".minecraft" / "runtime" / "java-runtime-epsilon" / "windows-x64" / "java-runtime-epsilon" / "bin" / "java.exe")
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    packages = local / "Packages"
    if packages.is_dir():
        for package in packages.glob("Microsoft.4297127D64EC6_*"):
            candidates.append(package / "LocalCache" / "Local" / "runtime" / "java-runtime-epsilon" / "windows-x64" / "java-runtime-epsilon" / "bin" / "java.exe")
    return candidates


def official_java(root, metadata):
    for candidate in java_candidates():
        if java_version_matches(candidate):
            return candidate.resolve()
    print("Preparing official Mojang Java 25.0.1 runtime...", flush=True)
    runtime_index = fetch_json(JAVA_INDEX_URL)
    matches = [item for item in runtime_index["windows-x64"]["java-runtime-epsilon"] if item["version"]["name"] == "25.0.1"]
    if not matches:
        raise RuntimeError("Mojang Java 25.0.1 runtime is unavailable")
    entry = matches[0]["manifest"]
    manifest_path = official_file(entry["url"], metadata / "java-runtime-epsilon-25.0.1.json", entry["sha1"], entry["size"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    runtime_root = root / "runtime" / "java-runtime-epsilon"
    runtime_root.mkdir(parents=True, exist_ok=True)
    for relative, item in manifest["files"].items():
        target = runtime_root.joinpath(*relative.split("/"))
        if item["type"] == "directory":
            target.mkdir(parents=True, exist_ok=True)
        elif item["type"] == "file":
            raw = item["downloads"]["raw"]
            official_file(raw["url"], target, raw["sha1"], raw["size"])
        else:
            raise RuntimeError(f"Unsupported Mojang Java runtime entry: {relative}")
    path = runtime_root / "bin" / "java.exe"
    if not java_version_matches(path):
        raise RuntimeError("Downloaded Mojang runtime is not Java 25.0.1")
    return path


def version_metadata(metadata):
    path = metadata / "26.3.json"
    if not path.is_file():
        appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        installed = appdata / ".minecraft" / "versions" / VERSION / f"{VERSION}.json"
        if installed.is_file():
            shutil.copy2(installed, path)
        else:
            index = fetch_json(VERSION_INDEX_URL)
            entries = [item for item in index["versions"] if item["id"] == VERSION]
            if not entries:
                raise RuntimeError("Minecraft 26.3 is absent from Mojang version metadata")
            entry = entries[0]
            official_file(entry["url"], path, entry["sha1"])
    value = json.loads(path.read_text(encoding="utf-8"))
    if value["id"] != VERSION:
        raise RuntimeError("Unexpected Minecraft version metadata")
    return value


def library_allowed(library):
    rules = library.get("rules")
    if not rules:
        return True
    allowed = False
    for rule in rules:
        if rule.get("os", {}).get("name", "windows") == "windows":
            allowed = rule["action"] == "allow"
    return allowed


def prepare_assets(root, version):
    asset_id = str(version["assetIndex"]["id"])
    assets = root / "assets"
    index_info = version["assetIndex"]
    index_path = official_file(index_info["url"], assets / "indexes" / f"{asset_id}.json", index_info["sha1"], index_info["size"])
    index = json.loads(index_path.read_text(encoding="utf-8"))
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    installed = appdata / ".minecraft" / "assets"
    installed_index = installed / "indexes" / f"{asset_id}.json"
    if installed_index.is_file() and digest(installed_index, "sha1").lower() == index_info["sha1"].lower():
        complete = True
        for item in index["objects"].values():
            value = installed / "objects" / item["hash"][:2] / item["hash"]
            if not value.is_file() or value.stat().st_size != item["size"]:
                complete = False
                break
        if complete:
            return installed
    count = 0
    for item in index["objects"].values():
        checksum = item["hash"]
        prefix = checksum[:2]
        target = assets / "objects" / prefix / checksum
        if not target.is_file() or target.stat().st_size != item["size"]:
            source = installed / "objects" / prefix / checksum
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file() and source.stat().st_size == item["size"]:
                shutil.copy2(source, target)
            else:
                official_file(f"https://resources.download.minecraft.net/{prefix}/{checksum}", target, checksum, item["size"])
        count += 1
        if count % 1000 == 0:
            print(f"Assets ready: {count}", flush=True)
    return assets


def prepare_dependencies(repository_root):
    if os.name != "nt" or sys.maxsize <= 2**32:
        raise RuntimeError("This PoC requires 64-bit Windows and Python 3")
    repository_root = Path(repository_root).resolve()
    root = repository_root / "dependencies"
    metadata = root / "metadata"
    metadata.mkdir(parents=True, exist_ok=True)
    print("Preparing official Minecraft 26.3 files...", flush=True)
    version = version_metadata(metadata)
    client_info = version["downloads"]["client"]
    server_info = version["downloads"]["server"]
    client = official_file(client_info["url"], root / "client" / "minecraft-26.3-client.jar", client_info["sha1"], client_info["size"])
    server = official_file(server_info["url"], root / "server" / "minecraft-26.3-server.jar", server_info["sha1"], server_info["size"])
    if digest(client, "sha256") != CLIENT_SHA256:
        raise RuntimeError("Minecraft client differs from the tested signed 26.3 build")
    logging_info = version["logging"]["client"]["file"]
    logging = official_file(logging_info["url"], root / "logging" / logging_info["id"], logging_info["sha1"], logging_info["size"])
    print("Preparing libraries and native FreeType...", flush=True)
    libraries = []
    natives = root / "natives"
    natives.mkdir(parents=True, exist_ok=True)
    for library in version["libraries"]:
        name = library["name"]
        if not library_allowed(library) or name.endswith(":natives-windows-arm64") or name.endswith(":natives-windows-x86"):
            continue
        artifact = library["downloads"]["artifact"]
        path = official_file(artifact["url"], root / "libraries" / Path(*artifact["path"].split("/")), artifact["sha1"], artifact["size"])
        if name.endswith(":natives-windows"):
            with zipfile.ZipFile(path) as archive:
                for entry in archive.infolist():
                    if entry.filename.lower().endswith(".dll"):
                        target = natives / Path(entry.filename).name
                        with archive.open(entry) as source, target.open("wb") as output:
                            shutil.copyfileobj(source, output)
        else:
            libraries.append(str(path))
    freetype = natives / "freetype.dll"
    classpath_file = root / "classpath.txt"
    classpath_file.write_text(";".join(libraries + [str(client)]), encoding="utf-8")
    logging_path_file = root / "logging-path.txt"
    logging_path_file.write_text(str(logging), encoding="utf-8")
    print("Preparing assets...", flush=True)
    assets = prepare_assets(root, version)
    java = official_java(root, metadata)
    game = root / "game"
    game.mkdir(parents=True, exist_ok=True)
    options = game / "options.txt"
    options.write_text('version:5023\nresourcePacks:[]\nincompatibleResourcePacks:[]\nfullscreen:false\npreferredGraphicsBackend:"opengl"\n', encoding="utf-8")
    trusted = game / "servers.dat"
    trusted_servers_file(trusted)
    manifest = {
        "client_jar": str(client),
        "server_runtime_jar": str(server),
        "server_launch_mode": "jar",
        "natives_dir": str(natives),
        "assets_dir": str(assets),
        "asset_index": str(version["assetIndex"]["id"]),
        "classpath_file": str(classpath_file),
        "logging_path_file": str(logging_path_file),
        "options_file": str(options),
        "trusted_servers_dat": str(trusted),
        "java_path": str(java),
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("Official dependencies ready", flush=True)
    return manifest


if __name__ == "__main__":
    prepare_dependencies(Path(__file__).resolve().parent)
