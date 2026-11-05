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

## Recovery expectations

- Joint updates and full installers verify the public immutable files before switching their active pointers.
- The legacy native publisher switches its pointer before public verification, then attempts to restore the previous pointer if verification fails. Serialize legacy native deployments to a channel.
- An interrupted client download stays in an unselected private generation.
- A client process that never confirms health is rolled back on the next clean start.
- Keep failed stages and receipts long enough to diagnose them; clean only directories whose owner token and exact plan are verified.

The included scripts assume a Linux host with Python 3, SSH and Nginx. The sample paths and hostnames are reserved for examples.
