# Branding

## Name

The product is **tallygate**, always lower-case, one word (even at the start of a sentence). On a
livestock farm the *tally gate* is the narrow gate where animals pass one at a time to be counted and
inspected; tallygate does the same with an agent's outbound connections.

## Logo

The mark is **four vertical tally bars crossed by a diagonal fifth stroke** — the classic "count of five".
The four bars double as the bars of a gate; the diagonal is a blue→cyan accent that reads as the stroke
that completes the count and as the active, automated check at the gate.

| File | Use |
|---|---|
| `control/app/static/logo.svg` | horizontal lockup (mark + wordmark) in the UI header and login page |
| `control/app/static/favicon.svg` | the mark on a rounded dark badge, as the browser-tab icon |
| `docs/images/logo-dark.svg` | README / dark backgrounds (light bars + wordmark) |
| `docs/images/logo-light.svg` | README / light backgrounds (dark bars + wordmark) |

The wordmark is two-tone: **tally** in the foreground colour, **gate** in the accent blue. Keep the mark's
geometry and the bar/diagonal relationship; recolour only for light vs dark. The bars may use the
surrounding text colour so the mark works anywhere.

## Colours

The control UI defines these as CSS variables on `:root` (`control/app/static/style.css`); the mark's
accent is `--blue`/`#3b82f6` fading to cyan `#22d3ee`.

| Token | Value | Used for |
|---|---|---|
| `--bg` | `#0f1115` | page background |
| `--panel` | `#181b22` | cards, header, tiles |
| `--line` | `#2c313c` | borders, separators |
| `--fg` | `#e6e6e6` | primary text, logo bars (dark) |
| `--muted` | `#8b93a3` | secondary text, table headers |
| `--blue` | `#3b82f6` | primary buttons, accent, "gate" in the wordmark |
| `--green` | `#22c55e` | allow / ok |
| `--red` | `#ef4444` | deny / error / connection-down dot |
| `--amber` | `#f59e0b` | ask / warning / badges |

## Typography

`system-ui` stack, 14 px / 1.45 in the UI. The wordmark uses the same system sans at weight 600 with a
slight negative letter-spacing.

## Tone

Plain, precise, a little dry. The UI explains *why* a thing is blocked or held, never just *that* it is.
Agent-supplied text (e.g. a grant reason) is always framed as a claim, not a fact.
