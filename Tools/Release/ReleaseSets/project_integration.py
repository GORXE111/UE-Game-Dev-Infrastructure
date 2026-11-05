"""Prerequisites for the project-specific Unreal release producers."""
from pathlib import Path
import re

import release_identity


class IntegrationError(ValueError):
    """The selected project checkout is missing an integration input."""


NATIVE_HASH_SCRIPT = Path("Tools/Release/Read-NativeSourceHash.ps1")
BUILD_SCRIPT = Path("Tools/Build-Project.ps1")
PACKAGE_SCRIPT = Path("Tools/Package-Project.ps1")


def project_inputs(project, *, build=False):
    project = Path(project).resolve()
    if len(project.parents) < 2:
        raise IntegrationError("--project must point to the game directory two levels inside its source checkout.")
    repository = project.parents[1]
    required = [
        project / "SampleGame.uproject",
        project / release_identity.SOURCE,
        repository / NATIVE_HASH_SCRIPT,
    ]
    if build:
        required.extend(repository / path for path in (BUILD_SCRIPT, PACKAGE_SCRIPT))
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise IntegrationError(
            "Select a complete SampleGame project checkout and install its project adapters. "
            "The public reference omits these project-owned inputs:\n  " + "\n  ".join(missing)
        )


def require_public_certificate(path, fingerprint):
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint) or fingerprint == "0" * 64:
        raise IntegrationError(
            "Configure CERTIFICATE_SHA256 with the approved Android public signing certificate digest "
            "before preparing or validating a signed APK."
        )
    if not Path(path).is_file():
        raise IntegrationError(f"Install the matching public Android signing certificate in DER format at {path}.")
