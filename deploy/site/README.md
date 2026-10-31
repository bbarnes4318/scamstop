# Deploying scamstop.pvnvoice.com

One container serves the download page, `/install`, the installer file with its
SHA-256, and the shared threat feed (`/v1/*`) that every ScamStop install syncs with.

1. DNS: `A  scamstop.pvnvoice.com  ->  <server IP>`
2. On the server, from a copy of this repo:
   `PORTAL_NETWORK=<caddy's docker network> docker compose -f deploy/site/compose.yml up -d --build`
   (the build downloads Python, libraries and the speech model once: about 5 minutes)
3. Add `Caddyfile.snippet` to the Caddyfile and reload Caddy. Caddy gets the HTTPS certificate.
4. Check: `curl -sI https://scamstop.pvnvoice.com/download/scamstop-installer-linux-x86_64.run`
   and `curl -s https://scamstop.pvnvoice.com/v1/stats`.

Upgrade: copy the new code, rerun step 2. The feed database lives in the `scamstop-feed` volume.
Feed admin: `docker exec scamstop-site scamstop feed-admin --db /data/feed.db installs`
