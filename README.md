# AI TRADER PRO v0.4 — synthetic paper simulation only

**Not deployed. No Binance API connection. No real prices, orders, balances or money movement.**

## Changes verified locally
- Seven-tab RTL PWA with real persisted **paper-equity** history chart (not live market history).
- Optional background paper worker: `PAPER_AUTO_WORKER=1` and `PAPER_TICK_SECONDS=15`; starts on server lifespan and stops on shutdown. One worker process only; **do not scale to multiple instances**. Engine only advances after user starts it and stops when risk lock triggers.
- Expiring 8-hour in-memory sessions with HttpOnly SameSite=Strict cookies; CSRF header and same-origin checks on protected writes; basic login rate limiting. Sessions are invalidated on restart. These are prototype protections, **not a completed security audit**.
- SQLite persistence for synthetic trades and equity history. Reset wipes paper history. Single-instance database only.
- Render blueprint prepared with paid persistent disk, secrets and optional paper worker. Deployment requires GitHub/Render access, account configuration and cost approval; not yet deployed.

## Local setup
```bash
pip install -r requirements.txt
pip install httpx
export APP_PASSWORD='a-long-unique-password'
export SESSION_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export PAPER_AUTO_WORKER=1
uvicorn app:app --host 127.0.0.1 --port 8000
python -m unittest -v test_paper
```

## Known limitations
- Synthetic deterministic prices, simplistic fill assumptions, no fee/slippage/gap modeling. Not validated for real-money use.
- No Binance data or private API support. No real-money execution route exists.
- Background worker is in-process, not durable across server downtime; do not run multiple replicas.
- No complete browser/device test, HTTPS deployment test, audit, production monitoring, backups or recovery drill.
- Session store and rate limits are in-memory. A production deployment requires more robust session storage, proxy/IP policies and further security review.

### v0.6 local security update (2026-11-16)
All `/api/` responses, including authentication errors and private paper-trading data, now carry `Cache-Control: no-store` and `Pragma: no-cache` to discourage browser/proxy caching. Added regression coverage; 12 unit tests passed locally. No live trading or Binance access added. Not deployed.

### v0.7 paper risk-lock change
When the simulated equity loss or consecutive-loss circuit breaker engages,
the paper engine now immediately closes its open simulated position at the
current synthetic tick price, records a `risk_liquidation` event, and stops.
This does not guarantee any real-world stop price and does not enable live orders.

## v0.8 agent validation
- Added regression test for Defensive (10%), Smart (20%) and Aggressive (30%) simulated entry allocation limits.
- Paper-only; no real exchange connectivity or orders.

### v0.9 — restart safety (paper only)
On FastAPI lifespan startup, a persisted `running=1` flag is changed to `running=0` and a `restart_pause` event is logged. Existing paper positions and risk locks remain unchanged. Explicit `start` is required to resume. Regression test: `test_099_restart_requires_manual_start`.

### v1.0 agent validation (2026-11-16)
Added regression coverage for a third consecutive simulated losing trade: the risk lock must stop the paper engine, close the open position, block restart, and retain a negative closed-trade P&L. This does not validate live exchange execution.

### v1.3.33 local safety update
Active in-memory login sessions are limited to 32. The earliest-expiring session and its CSRF token are evicted when a new login would exceed the cap. No live trading or Binance connectivity is enabled.

### v1.3.34 local safety update
- Logout responses now explicitly use `Cache-Control: no-store`; regression test added. No changes to the seven UI sections or live trading configuration.

### v1.3.35 local cache safety update
The service worker no longer caches the dashboard HTML, purges prior shell caches on activation, and retains only the public manifest for offline fallback. Seven tabs unchanged; paper-only.

### v1.3.36 session eviction race safety
The session endpoint now responds with HTTP 401 instead of HTTP 500 if a concurrent login evicts its CSRF token after authentication. No UI or live-trading changes.

### v1.3.37 concurrent login response safety
Capture the new CSRF token under the session lock so concurrent session eviction cannot cause a 500 while constructing the login response. Added regression coverage. Paper-only; seven navigation tabs unchanged.

### v1.3.38 CSRF concurrent-session safety
CSRF secrets are read once under the session lock to prevent a concurrent eviction from raising an internal error. Paper trading only.

### v1.3.40 Login content-type validation
Reject non-JSON login requests with HTTP 415 before credential parsing; regression test included. Paper-only mode and all seven navigation tabs unchanged.

### v1.3.42 bounded login streaming
Read login request data incrementally with a 4096-byte limit instead of buffering an unlimited body. Regression test included; paper-only, seven tabs unchanged.
