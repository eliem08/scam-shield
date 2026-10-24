# Architecture — scam-shield

## 1. Scope
Explainable scam detection for messages and call transcripts aimed at older adults, plus a
family safe-word protocol.
**MVP:** weighted rule engine (tactic signals), look-alike domain detection, link analysis, verdict and advice, PBKDF2 safe word.
**Product:** forward-to-check email/SMS, live call screening, family alert dashboard, ML second opinion.

## 2. System context
```mermaid
flowchart LR
  Senior -->|forwards message / call audio| Intake[Email / SMS / call intake]
  Intake --> STT[Speech-to-text] --> Engine
  Intake --> Engine[Detection engine]
  Engine --> Verdict[Plain-language verdict]
  Verdict --> Senior
  Engine -->|high risk| Family[Adult-child alert]
```

## 3. Detection model
Signals are independent detectors, each with a weight and evidence:
- tactic lexicons: urgency, secrecy, gift cards, untraceable payment, family emergency, authority,
  credential request, prize, refund lure
- sender domain look-alike: homoglyph normalisation, Levenshtein = 1 to a brand (length ≥ 5), brand
  embedded in another domain, punycode
- links: raw IP, URL shortener, shown-host ≠ actual-host

`score = Σ strongest weight per signal (+10 if ≥ 3 tactics), capped at 100` → `safe < 20 ≤ suspicious < 50 ≤ likely scam`.

## 4. Design decisions
- **Explainability over accuracy-at-all-costs.** The user has to *believe* the verdict, so every
  point traces to quoted evidence and a plain-English action.
- **Combination bonus.** Real scams stack tactics (urgency + secrecy + gift cards), and single
  signals are often benign.
- **Safe words are hashed with PBKDF2-SHA256** (200k iterations) and a salt, then normalised for
  case and whitespace. The plain word is never stored.
- An ML classifier is a *second opinion* layer later, never the sole decider.

## 5. Production architecture
Intake (SES / Twilio), stateless engine service, Postgres (users, family links, events), and push
alerts. Call screening uses streaming STT with rolling-window scoring and a prompt to "ask for the safe word".

## 6. Risks
False positives erode trust, so thresholds are tuned on a labelled corpus. Lexicons need i18n.
The adversary adapts, so the lexicon must update without a release (remote config).
