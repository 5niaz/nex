# Nexus

Lightweight status and endpoint gateway.

- Exposes a private status page at `/s/<key>`
- Provides a subscription-style endpoint list at `/sub/<key>`
- Health endpoint: `/status` and `/healthz`
- Relays WebSocket traffic to a local core process on ports 10001–10003

## Run

```bash
bash start.sh
```

The service listens on port 8000.

## Notes

- Credentials live in `creds.json` and `config.json`.
- Endpoint descriptors are generated dynamically from the request Host header.
- Additional template strings are provided for reference only and require a dedicated server.
