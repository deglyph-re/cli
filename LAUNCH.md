# deglyph — launch & business setup checklist (PRIVATE)

> This file is gitignored on purpose: it holds business/account/legal setup notes
> that should not be published with the open-source repo. Keep it local.

Full reasoning lives in the approved plan; this is the actionable checklist.

## 1. Domain
- [ ] Register **`deglyph.dev`** at **Cloudflare Registrar** (at-cost, free DNS,
      WHOIS privacy included). Fallbacks if taken: `deglyph.sh`, `deglyph.tools`,
      `getdeglyph.com`. Avoid `.io` (expensive, ownership uncertainty).
- [ ] Point DNS at Cloudflare; enable proxy (orange cloud) for TLS + DDoS.

## 2. Hosting
- [ ] **Marketing site + docs:** Cloudflare Pages (free) or Vercel. A single
      landing page + a docs section to start.
- [ ] **API backend** (`api.deglyph.dev`): **Fly.io** to start (scale-to-zero,
      ~$5/mo, low ops). If cost matters more than convenience, a **Hetzner** VPS
      (~EUR 4/mo). Put Cloudflare in front.
- [ ] **Database + auth:** **Supabase** (managed Postgres + auth, generous free tier).

## 3. Payments (pick one)
- [ ] **Lemon Squeezy** or **Paddle** — Merchant of Record. They collect and remit
      global VAT / US sales tax for you. Strongly recommended for a solo seller:
      removes the biggest legal/tax burden. Slightly higher fees than Stripe.
- [ ] **Stripe** — lower fees, more control, but you must handle tax yourself
      (Stripe Tax helps). Choose only if you want the control and will do the tax work.
- [ ] Set up products: **Pro** (~$10/mo: hosted AI, agentic mode, cloud sync) and
      **Team/Business** (~$30/seat/mo: scan cloud, shared annotations, SARIF, SSO).
      Offer monthly + annual (annual ~2 months free).

## 4. Entity & legal
- [ ] Form an entity before taking money (LLC / sole-prop per your jurisdiction; an
      EU/US entity affects tax — a Merchant of Record sidesteps most of this).
- [ ] Publish **Terms of Service**, **Privacy Policy** (disclose: hosted AI sends
      disassembly to your server then Anthropic), and an **Acceptable-Use Policy**
      (authorized reverse engineering / your-own-binaries only — important for a
      dual-use tool; mirrors the threat model already in `SECURITY.md`).
- [ ] **Trademark "deglyph"** (word mark) in your primary market. The GPLv3 code is
      free to fork (forks must stay GPLv3/open), but the name/brand stays yours —
      that, plus copyleft, is what protects the business. Do a quick clearance
      search first.
- [ ] Anthropic API: a billing-capped key for the hosted tier; monitor usage so a
      runaway user can't rack up cost faster than they pay (rate-limit per account).

## 5. Repo / open-core hygiene (mostly handled in code)
- [ ] Keep the public repo GPLv3 and free of secrets. The hosted server is a SEPARATE
      PRIVATE repo (GPLv3 copyleft covers only distributed code, not your server).
- [ ] Consider moving the GitHub repo under a dedicated org (e.g. `deglyph`) rather
      than a personal account, so the project reads as a product. Update the URLs in
      `pyproject.toml` / `CHANGELOG.md` / the About dialog if you do.
- [ ] Enable GitHub: Private Vulnerability Reporting (Security tab), Dependabot
      (already configured), branch protection on `main`.

## 6. Launch / marketing
- [ ] Record an asciinema or GIF demo (the `samples/demo.exe` analysis view).
- [ ] Cut the first release: tag `v0.1.0` -> the release workflow publishes to PyPI
      (register the Trusted Publisher for `deglyph` on PyPI first — see CONTRIBUTING).
- [ ] Launch posts: Show HN, r/ReverseEngineering, r/netsec, Lobste.rs. **Lead with
      the defensive angle** ("find hardcoded secrets in your release binary in 10s",
      "add a binary secret-scan to CI in 5 lines") — bigger audience than RE hobbyists.
- [ ] Ship `deglyph scan` as a GitHub Action so it spreads through CI pipelines.
- [ ] Set GitHub repo topics; the PyPI keywords are already expanded.

## Reality check
Solo + niche: expect $0–a few hundred/mo for months, ~$1–2k/mo with traction,
$3–10k+/mo only with active B2B selling. The cloud/appsec platform (not individual
RE subscriptions) is where the real ceiling is. Treat early revenue as validation.
