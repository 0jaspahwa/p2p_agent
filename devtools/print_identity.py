# devtools/print_identity.py
from __future__ import annotations

import sys

from agent.identity import AgentIdentity


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m devtools.print_identity <path-to-identity.pem>")
        sys.exit(1)

    identity = AgentIdentity.load_or_create(sys.argv[1])
    print(identity.agent_id)


if __name__ == "__main__":
    main()
