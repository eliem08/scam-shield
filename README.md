# scam-shield

> **Norton for AI scams** — protect your parents from fake voices and emails.

Voice clones of a grandchild "in jail", perfectly written phishing emails,
fake bank texts. AI made scams cheap and convincing. `scam-shield` is the
detection engine behind a family protection app: paste or forward a message
(or a call transcript) and get a plain-language verdict.

## What the MVP does

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
