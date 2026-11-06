# Server gateway

The gateway has two separate surfaces:

| Surface | Access | Purpose |
| --- | --- | --- |
| Upload control plane | Trusted operator with SSH shell access | Create and own one release stage, upload files, verify them, and request promotion |
| Public download plane | HTTPS GET/HEAD/Range only | Serve signed metadata and immutable versioned files to installed clients |

The hosting code in `Tools/Release/PlayerHosting/` and `NativeHosting/` keeps the upload credentials away from the player. A stage is bound to a unique token and a frozen plan. The server checks every byte before moving it into an immutable release directory. The current pointer changes only after an optimistic concurrency check against the state observed during planning.

## Configure the sample gateway

1. On a disposable Linux host, install [the TLS vhost](../Tools/Release/PlayerHosting/nginx-gateway.example.conf) at `/etc/nginx/sites-available/updates.example.com`. Install the [player fragment](../Tools/Release/PlayerHosting/nginx-player.locations.conf) and [native fragment](../Tools/Release/NativeHosting/nginx-native.locations.conf) at the two snippet paths in the vhost.
2. Supply your hostname and TLS certificate paths. The public publisher currently binds its expected origin in `Tools/Release/PlayerHosting/players.py`. Update that value and the runtime configuration to match. If you change the vhost filename, storage root, channel allowlist or URL prefix, update the corresponding publisher and remote worker constants together. Keep the joint version route inline in the vhost so the worker's stage guard can find it.
3. Give the deployment account write access to its release directories and Nginx read access to public files. Provision the SSH host key in known_hosts. Enable the vhost and run `nginx -t` before reloading.
4. Check the current manifest, a known versioned file and a missing versioned file. Current metadata and missing files must have `Cache-Control: no-store`. A published version file must support HEAD and Range with identity encoding and advertise `immutable`.

Joint routes map current metadata to `channels/<channel>/current/` and versioned files to `channels/<channel>/releases/<id>/versions/<id>/` under `/srv/ue-game-updates`. Nginx accepts GET and HEAD on these routes. The SSH workers execute publisher-supplied code with the operator's permissions. Use a separate deployment account and scope its filesystem access to the release tree.

## Verify public delivery independently

Run the readback from a client network using the public HTTPS hostname. Supply the immutable `prepared.json` and its SHA-256 from a trusted build or publication receipt. The tool accepts joint release plans and full installer plans. A joint release also uses the pinned manifest and signature beside the plan in `payload/`.

```powershell
python -X utf8 -B .\Tools\Release\PlayerHosting\verify_public_delivery.py `
  --prepared D:\ReleaseEvidence\Prepared\prepared.json `
  --expected-plan-sha256 $trustedPlanSha256 `
  --origin https://updates.example.com --prefix /samplegame `
  --report-dir D:\ReleaseEvidence\PublicReadback --check-current
```

Use `--check-current` when the prepared version is expected to be active. It checks current metadata before and after the immutable downloads. The verifier authenticates the joint manifest with the pinned key, streams and hashes every public immutable file without retaining the large downloads, and verifies HEAD and both byte ranges for each installer or the largest joint payload file. Missing versioned files must return 404 with `no-store`. Readback uses GET and HEAD over standard HTTPS. Completed files are recorded in `public-progress.jsonl` even when a later check fails. The report includes observed cache headers. CDN provider or edge-cache identity requires separate provider evidence.

## Exercise promotion on a disposable Nginx instance

On Linux with Nginx, Python 3 and `cryptography`, run the following with a fresh scratch directory and an unused loopback port.

```sh
python3 -B ./Tools/Release/PlayerHosting/verify_nginx_promotion.py \
  --nginx /usr/sbin/nginx --output /tmp/ue-gateway-qa --port 18443
```

The runner relocates the example vhost and routes to its scratch tree, generates a disposable TLS identity and signs two fixture releases. It uses the real release worker to promote and roll back, intentionally reads a manifest and signature across both switches, and verifies that the previous immutable release is still downloadable. The fixture also checks protected pointers, 404 caching and denied writes. It binds only to loopback and records the result in `report.json`.

## Recovery expectations

- Joint updates and full installers verify the public immutable files before switching their active pointers.
- The legacy native publisher switches its pointer before public verification, then attempts to restore the previous pointer if verification fails. Serialize legacy native deployments to a channel.
- An interrupted client download stays in an unselected private generation.
- A client process that never confirms health is rolled back on the next clean start.
- Keep failed stages and receipts long enough to diagnose them; clean only directories whose owner token and exact plan are verified.

The included scripts assume a Linux host with Python 3, SSH and Nginx. The sample paths and hostnames are reserved for examples.
