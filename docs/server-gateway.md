# Server gateway

The gateway has two separate surfaces:

| Surface | Access | Purpose |
| --- | --- | --- |
| Upload control plane | Authenticated deployment identity over SSH or a private relay | Create and own one release stage, upload files, verify them, and request an atomic promotion |
| Public download plane | HTTPS GET/HEAD/Range only | Serve signed metadata and immutable versioned files to installed clients |

The hosting code in `Tools/Release/PlayerHosting/` and `NativeHosting/` keeps the upload credentials away from the player. A stage is bound to a unique token and a frozen plan. The server checks every byte before moving it into an immutable release directory. The current pointer changes only after an optimistic concurrency check against the state observed during planning.

The nginx examples use `updates.example.com` and `/srv/ue-game-updates` placeholders. Public routes should have narrow path allow-lists, no directory listing, HTTPS, correct MIME types, identity encoding for package downloads, no-cache rules for current manifests, immutable cache headers for versioned payloads, and bounded 404 caching. Upload routes must not be exposed by the static server.

## Recovery expectations

- Upload failure leaves the active version untouched.
- Promotion failure restores the previous current pointer.
- An interrupted client download stays in an unselected private generation.
- A client process that never confirms health is rolled back on the next clean start.
- Keep failed stages and receipts long enough to diagnose them; clean only directories whose owner token and exact plan are verified.

The included scripts assume a Linux host with Python 3, SSH, systemd, and nginx. Replace the sample paths and review the remote commands before connecting a host. No production host address or deployment key is included here.
