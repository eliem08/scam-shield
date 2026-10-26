<!-- sell-kit:start -->
# Scam Shield

[![CI](https://github.com/eliem08/scam-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/eliem08/scam-shield/actions/workflows/ci.yml)

> **Protect your parents from fake voices, texts and phishing emails.**

**Who it's for:** Adult children worried about scams targeting their parents.

**The problem:** Grandparent and impersonation scams now use AI voices and perfect phishing, and older adults lose life savings to them.

**What you get:** Explainable scam scoring for messages and call transcripts, look-alike domain and link checks, and a family safe word that only you know.

## Quickstart

Customers receive a release archive with the wheel and the examples. Python 3.10+ and no other dependencies.

```bash
pip install scam_shield-0.1.0-py3-none-any.whl
scam-shield check "Grandma it's me, I'm in jail. Don't tell mom. Buy Apple gift cards now."
scam-shield check "Dinner at 6?" --sender mom@example.com
```

## Web app and API

Every command is also a JSON API endpoint and a browser form, served by the built-in web app.

```bash
scam-shield-web --port 8000          # then open http://127.0.0.1:8000
scam-shield-web keys create --label "first customer"   # prints an API key (stored hashed)
docker build -t scam-shield . && docker run -p 8000:8000 -e API_KEYS=sk_... -v scam-shield-data:/data scam-shield
```

Every API call needs `Authorization: Bearer <key>` once any key exists; a server on a public address refuses to start without one. Calls are rate-limited per key (60/min, `--rate`) and metered: `scam-shield-web usage` prints calls per key for billing.

Endpoints: `POST /api/check`, `POST /api/safeword-set`, `POST /api/safeword-verify`, plus `GET /healthz` and `GET /api/spec` (machine-readable field list).
Files are sent as `{"name": ..., "content": ...}`, folders as `{"files": [...]}` or a base64 zip.

## Deploy and sell

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/eliem08/scam-shield)

`render.yaml` (one click, above) and `fly.toml` (`fly launch --copy-config`) both run the Dockerfile with a persistent `/data` volume and a `/healthz` check.
To sell self-serve, set four variables and point a Stripe webhook at `https://<your-host>/billing/webhook` (events `checkout.session.completed` and `customer.subscription.deleted`):

| Variable | Example |
|---|---|
| `STRIPE_SECRET_KEY` | `sk_live_...` |
| `STRIPE_WEBHOOK_SECRET` | `whsec_...` |
| `STRIPE_PRICES` | `team=price_123,business=price_456` |
| `PUBLIC_URL` | `https://scam-shield.example.com` |

Buyers pick a plan on `/pricing`, pay on Stripe Checkout and see their API key once on the success page. Cancelling the subscription revokes the key. A selling server always requires a key.

## Pricing

Every plan starts with a 14-day free trial. Prices in USD, billed monthly unless noted.

| Plan | Price | Includes |
|---|---|---|
| **Personal** | $4 per month | Unlimited message checks; Link and domain checks; Safe word |
| **Family** | $9 per month | Up to 6 people; Shared safe word; Plain-language advice |
| **Care Partner** | $199 per month | For banks, clinics and care homes; Bulk checks; Priority support |

To start a trial or buy a plan, [request access](https://github.com/eliem08/scam-shield/issues/new?title=Scam%20Shield%20trial&labels=sales).

## Licence

Proprietary. Copyright (c) 2026 eliem08. All rights reserved. Use requires a paid plan or an active trial; see [LICENSE](LICENSE).
<!-- sell-kit:end -->

## What it does

- **Risk scoring** of emails, texts and call transcripts with explainable signals:
  - urgency & secrecy pressure ("act now", "don't tell anyone")
  - untraceable payment asks (gift cards, wire, crypto, Zelle, cash courier)
  - family-emergency script ("grandma it's me", "I'm in jail", "new number")
  - authority impersonation (IRS, Social Security, police, bank fraud dept)
  - credential / code requests ("read me the code we sent")
  - **look-alike sender domains** (edit distance + digit swaps + punycode) vs. known brands
  - links whose visible text doesn't match the real host, raw-IP links, URL shorteners
- Verdict `safe / suspicious / likely scam` + **what to do next** in plain English
- **Family safe word**: store a salted hash; verify a caller who claims to be family

## Quickstart

```bash
pip install -e .
scam-shield check "Grandma it's me, I'm in jail, please don't tell mom. Buy $500 of Apple gift cards"
scam-shield check --file email.txt --sender security@paypa1.com
scam-shield safeword set "purple pancakes" && scam-shield safeword verify "purple pancakes"
```

## Roadmap

- Forward-to-check email address and SMS number for seniors
- Call screening: live transcript scoring + "ask for the safe word" prompt
- Family dashboard: alerts to adult children when a high-risk message arrives
- Deepfake-voice artefact detection on recordings

## Development

Zero runtime dependencies; Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m unittest discover -s tests -t .           # unit + CLI smoke tests
ruff check . && ruff format --check .               # lint + format
```

```
scam_shield/core.py       domain logic (pure, importable, fully tested)
scam_shield/__main__.py   CLI (`scam-shield ...` / `python -m scam_shield ...`)
tests/                unit tests + generated CLI smoke tests
```

CI runs lint and tests on Ubuntu and Windows across Python 3.10, 3.12 and 3.13.
Design, data model, trade-offs and production path: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

Part of the [agent-economy](https://github.com/eliem08/agent-economy) portfolio (idea #14).
