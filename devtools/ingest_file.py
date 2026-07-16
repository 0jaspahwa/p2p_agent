
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from agent.storage import LocalStorage


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="path to the local file to share")
    parser.add_argument("--storage-root", default="./downloads", help="this agent's storage root")
    args = parser.parse_args()

    src = Path(args.file)
    if not src.exists():
        print(f"file not found: {src}")
        return

    print("hashing file...")
    hasher = hashlib.sha256()
    with src.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    file_hash = hasher.hexdigest()
    file_size = src.stat().st_size

    storage = LocalStorage(args.storage_root)

    if await storage.exists(file_hash):
        print("file already present in storage (identical content already shared).")
    else:
        async def _stream():
            with src.open("rb") as f:
                while chunk := f.read(1024 * 1024):
                    yield chunk

        print("copying into storage...")
        await storage.write_stream(file_hash, _stream())

    meta_path = Path(args.storage_root) / f"{file_hash}.meta"
    meta_path.write_text(json.dumps({"file_name": src.name}), encoding="utf-8")

    print()
    print("=" * 60)
    print("FILE READY TO SHARE")
    print(f"  hash: {file_hash}")
    print(f"  size: {file_size} bytes")
    print(f"  name: {src.name}")
    print("=" * 60)
    print()
    print("Send the hash (and size) to whoever you want to have access.")


def cli_main():
    """Synchronous entry point for the console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()