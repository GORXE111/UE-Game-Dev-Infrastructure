"""Read-only validation of a signed release set; never activates or confirms it."""
import argparse
import json
from pathlib import Path

import release_set as sets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args()
    trust = sets.parse(sets.read_bounded(args.trust, sets.MAX_MANIFEST))
    raw = sets.read_bounded(args.manifest, sets.MAX_MANIFEST)
    signature = sets.read_bounded(args.signature, 8192)
    sets.ed25519_verifier(trust["publicKeyHex"])(raw, signature)
    value = sets.manifest(raw, trust)
    sets.verify_tree(args.payload, value["files"])
    print(json.dumps(dict(status="signed-inventory-verified", platform=value["platform"], releaseId=value["releaseId"],
                          buildId=value["buildId"], files=len(value["files"]), productionQualified=False,
                          gameLaunched=False, stateChanged=False), indent=2))


if __name__ == "__main__":
    main()
