---
name: new-help-page
description: Add or restructure a page in the doc/help manual (the JSON-indexed Markdown set rendered by the website). Use when the user asks for new user documentation, a help topic, or manual changes.
---

The manual contract lives in the "help manual" entry of
`doc/claude/architecture.md`; read it first. The hard rules:

1. Every page is a Markdown file in `doc/help/` with a matching entry in
   `doc/help/help.json` (`{id, title, section, file}`). A page without an
   index entry never renders; an index entry without a file 404s. Ids are
   unique; pick the section from the ones already present in `help.json`.
2. Cross-link other pages by file name (`[Title](Other-Page.md)`); the site
   rewrites those to hash routes. A link to a file missing from the index
   silently fails to rewrite.
3. Prose follows the tone contract (CLAUDE.md, Comments): neutral voice, no
   marketing, no first person, ASCII only. `python3 scripts/verify.py
   doc/help/<file>.md` must be clean.
4. Results language: anything heuristic is a candidate with its limits
   stated. Every analysis page says what the method misses; follow the
   pattern in `doc/help/Limitations.md` and `doc/help/Heuristics.md`.
5. End the page with a "See also" list of the most related pages.

Edits go live when main is pushed (the website fetches raw files at
runtime), so treat every help edit as published on merge.
