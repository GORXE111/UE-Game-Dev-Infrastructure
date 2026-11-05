# Security and configuration

This repository is a public, sanitized source snapshot. It intentionally has no live endpoint, deployment credential, signing private key, keystore, game package, production certificate, or artwork.

Before adapting it:

1. Choose a package name, project ID, channels, engine identity, and an application-specific release protocol identity.
2. Generate signing identities in a secure environment. Store private signing and deployment material outside the checkout.
3. Replace the all-zero Windows public-key and Android certificate placeholders with the trust identities used by your installed bases. Confirm Android base and future APKs use the intended same application identity.
4. Configure HTTPS origin, DNS, SSH host keys, remote storage paths, nginx routes, and firewall rules from your own reviewed deployment configuration.
5. Ensure server-side upload credentials cannot change unrelated sites or channels. Keep the public static gateway read-only.
6. Use new development keys and channels for test builds. Never point a development build at a production signing key or channel.
7. Keep a known-good full installer and save backup before changing the update client, bootstrap, or compatibility schema.

The code validates paths, signatures, release identity, and payload digests, but correctness also depends on how a project integrates the plugin, builds the package, protects keys, provisions the server, and tests rollback on real target devices.

There is no license file. The repository is visible for technical review; re-use or redistribution requires permission from the maintainers.
