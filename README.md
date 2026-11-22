<!-- coderabbit-ai-generated:v1 -->

# Visitor log and port scanner

This repository contains a GitHub Pages site, a Cloudflare Worker that stores visit IPs, and a separate Python TCP scanner. The site tells visitors that visit information is recorded. The admin page has no link on the site; its source is public, but the log API requires a secret token. Logs stay in Cloudflare KV, not in the GitHub repository.

## Deploy the log backend

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:18ab01880c924ec96d668208ca7368d6ff6503a8cc3ad9df5beceb829139d8e9 -->

1. Create a Cloudflare account and use Node.js 22.12 or later. In a terminal, go to `worker/` and authenticate: `npx wrangler login`.

<!-- /coderabbit-ai-generated:v1 -->
2. Run `npx wrangler kv namespace create VISITS`. Copy the returned namespace ID into `worker/wrangler.toml`, replacing `REPLACE_WITH_KV_NAMESPACE_ID`.
3. In `worker/wrangler.toml`, set `SITE_ORIGIN` to the exact origin hosting the site, for example `https://YOUR-USERNAME.github.io` (no repository path or trailing slash). For a custom domain, use that origin instead.
4. Generate a strong token with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Store it safely; do not commit it. Run `npx wrangler secret put ADMIN_TOKEN` from `worker/` and paste the token when prompted. The token must be at least 32 characters.
5. Run `npx wrangler deploy` in `worker/`. Copy the Worker URL that Wrangler prints. Configure Cloudflare rate limiting for the public `/api/visit` endpoint if you expose it publicly; the origin check is not protection against direct scripted requests. Check Cloudflare's current quotas and pricing before making the site public.

## Deploy the website

1. Set `workerUrl` in `public/config.js` to the Worker URL, without a trailing slash. It is public configuration, not a secret.
2. Customize `public/index.html`, including the placeholder email address, and keep its visitor logging notice accurate.
3. Push the files to the repository's `main` branch. In GitHub repository settings, choose **Pages → Build and deployment → Source → GitHub Actions**. The included workflow publishes `public/` on each push to `main`. Alternatively, publish that folder with your preferred static hosting.
4. Visit the site's `admin.html` path and enter your admin token. The token stays in the page's memory and is cleared by Sign out or closing the page. Do not share it or put it in the repository. The admin URL itself is not secret: the API token protects the log.

The worker records the IP from Cloudflare, the page path without query strings, and a UTC timestamp. Entries expire after 30 days. KV is eventually consistent, so new visits can take time to appear or pagination can change while writes occur. If access is lost or the token leaks, rotate it with `npx wrangler secret put ADMIN_TOKEN`. The log endpoint does not enforce per-visitor rate limits.

## Port scanner

Python 3.9 or newer is required; no packages are needed. Only scan systems you own or are authorized to test.

```sh
python3 scanner.py example.com
python3 scanner.py 127.0.0.1 --ports 22,80,443,8000-8010 --json
python3 scanner.py example.com --ports 1-1024 --ports-only
```

The scanner uses TCP connections. Its service names are port-based guesses, not detected service identities. Checks cover a reachable Telnet port, Redis PING without authentication, exposed Memcached statistics, certificate verification on ports 443 and 8443, and basic HTTP/HTTPS header checks on common web ports. They are limited signals, not a complete vulnerability assessment; no finding does not mean a host is secure. HTTP checks send one HEAD request and do not follow redirects. Filtered, slow, or custom-port services may be missed.

## Development and tests

```sh
python3 -m http.server 8000 --directory public
npm test
python3 -m unittest discover -s tests -p 'test_*.py'
```

The local static preview does not store visits until the deployed Worker URL is configured. The tests use local fixtures; they do not contact Cloudflare or scan external hosts.
