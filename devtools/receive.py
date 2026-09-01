
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

import httpx


def _fmt_size(n: int) -> str:
    """Human-readable byte size, e.g. 10529020 -> '10.0 MB'."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GB"  # unreachable, keeps type checkers happy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file_hash", help="the hash your friend sent you")
    parser.add_argument(
        "--port", type=int, default=9000,
        help="your agent's control API port (matches P2P_SERVER_PORT / cfg.server.port)",
    )
    parser.add_argument("--poll-interval", type=float, default=1.0)
    args = parser.parse_args()

    base_url = f"http://127.0.0.1:{args.port}"

    print(f"requesting {args.file_hash[:16]}...")
    try:
        resp = httpx.post(f"{base_url}/downloads", json={"file_hash": args.file_hash}, timeout=10.0)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        print(f"could not reach your agent's control API at {base_url} — is it running? ({e})")
        sys.exit(1)

    download_id = resp.json()["download_id"]

    while True:
        status_resp = httpx.get(f"{base_url}/downloads/{download_id}", timeout=10.0)
        data = status_resp.json()
        status = data["status"]

        if status == "pending":
            print("\rwaiting to start...", end="", flush=True)
        elif status == "running":
            downloaded = data.get("bytes_downloaded", 0)
            total = data.get("total_bytes_expected")
            if total:
                pct = (downloaded / total) * 100 if total else 0
                line = f"downloading... {_fmt_size(downloaded)} / {_fmt_size(total)} ({pct:.0f}%)"
            else:
                
                line = f"downloading... {_fmt_size(downloaded)}"
      
            print(f"\r{line}".ljust(70), end="", flush=True)
        elif status == "complete":
            result = data["result"]
            print()
            print(f"done! {result['total_bytes']} bytes, verified={result['verified']}")
            if result.get("file_name") and result.get("storage_path"):
                import shutil as _shutil

                safe_name = os.path.basename(result["file_name"]) or result["file_hash"]
                export_path = os.path.join(os.getcwd(), safe_name)
                try:
                    _shutil.copy2(result["storage_path"], export_path)
                    print(f"saved as: {export_path}")
                except OSError as e:
                    print(f"(couldn't copy to friendly filename: {e})")
                    print(f"raw file is at: {result['storage_path']}")
            else:
                print(f"(no filename metadata — raw file at: {result.get('storage_path', 'unknown')})")
            return
        elif status == "failed":
            print()
            print(f"FAILED: {data.get('error', 'unknown error')}")
            sys.exit(1)

        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()