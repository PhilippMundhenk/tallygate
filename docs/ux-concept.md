# UX concept for the control UI

One small vocabulary, used the same way on every page. New UI must be built from these parts; a unit test
(`tests/unit/test_ui_conventions.py`) checks the mechanical rules. Sources are listed at the end.

## 1. Page anatomy

1. **Title, at most one line of purpose, then content.** No intro paragraph that restates the title, no
   heading that repeats the menu entry twice.
2. **Sections are cards only when a page has several peer groups.** Never a card inside a card.
3. **The order on a page is: act → see → configure.** Tools the operator reaches for first (search, test,
   history) sit on top, the long list below, rarely used configuration last.

## 2. Buttons

| Rank | Class | Use |
|---|---|---|
| Primary | `button` (filled) | The single main action of a view or form. **At most one per card/form.** Read-only pages (Overview, Log) have none. |
| Secondary | `.secondary` | Every other action, and Cancel. |
| Ghost | `.ghost` | Low-emphasis and row actions (Edit, Undo), links that act. |
| Danger | `.danger` | Destructive or security-lowering actions. Always confirmed (see 6). |

- **A button is an action.** It never shows a selected state and never only reveals text. State is shown by
  a select, radios, a checkbox or a switch.
- **Labels are verb + noun in sentence case**: "Add rule", "Create grant", "Save settings". No "OK", no bare
  nouns, no trailing punctuation except "…" when a form opens.
- **One verb per meaning:** Add (new row in a list), Create (new object with a form), Edit, Save, Delete
  (object is gone), Remove (take out of a set / undo an override), Revoke (end an active grant), Undo
  (reverse a shortcut), Test, Allow / Deny (decisions).
- More than three actions in one row go behind a "More" menu on narrow screens only.

## 3. Choosing a control

| Situation | Control |
|---|---|
| On/off, applies at once | **checkbox** that saves on change and confirms with a toast |
| On/off inside a form with Save | checkbox |
| 2–5 exclusive options | **select** (short labels) or radios (options need a description) |
| Many options | select |

Never mix instant-apply controls and Save-required controls in one card.

## 4. Help: three levels, one pattern each

| Level | Pattern | Rules |
|---|---|---|
| Hint | `<p class="hint">` or `<small>` under a field | One short sentence. No links. Only where most users need it. |
| Help | `<details class="help">` (ⓘ + question-style label) | Everything longer. Text only — **never contains controls**. The docs link is its last line. |
| Docs | link inside a help disclosure | Never a bare "how"/"here"/"More" link on the surface. |

Tooltips (`title`) only name icon-only controls; they never carry instructions.

## 5. Disclosure of controls

`<details class="more">` (caret + plain label such as "Advanced options") hides rarely used **controls**. It
looks like a control, not like help. One level deep. Collapsible **content panels** (History, Search, Raw
policy) are `<details class="card">`.

## 6. Destructive and security-lowering actions

- Trigger is a `.danger` button; the confirmation is the inline arm-and-confirm (`confirmClick`): the
  question names the object and the consequence ("Delete grant nas-ssh?", "Delete the block of
  192.168.0.0/16? The agent will be able to reach these addresses if another rule or the default allows it.").
- Reversible actions are not confirmed; they offer Undo instead.

## 7. Status vocabulary

| Element | Class | Use |
|---|---|---|
| Status | `.status.ok / .warn / .bad / .off` | A state word with a dot: **active**, **off**, **waiting**, **failed**, **done**. Colour is never the only signal. |
| Tag | `.tag` | Neutral attribute: local, read, write, config file. |
| Count | `.badge` | A number in the menu. |
| Claim | `.claim-badge` | Agent-written, unverified text. Same badge everywhere. |

Access values are always the words **allow / ask / deny**. No emoji as icons or status markers; the
symbols ✓ ✕ ! are allowed inside status text only.

## 8. Feedback

- **Toast**: transient success ("Rule added"). Past tense of the button's verb.
- **Inline alert** (`.alert.warn / .bad`): errors and anything that needs action, next to the cause, persistent.
- **Empty state**: one sentence saying why the list is empty and, where it exists, the one next action.
  No celebration emoji.

## 9. Words

Sentence case everywhere. One term per concept: *destination* (not host/target in prose), *rule*, *grant*,
*request*, *blocked range*, *Quick settings*, *Settings*, *Setup*. The agent is "the agent". Numbers with
units ("15 min", "1 h"). No "click here", no "please", no exclamation marks.

## 10. Density and accessibility

- Type scale: 20 px page title (`h2`), 15 px section (`h3`), 13 px body, 12 px meta/hint.
- Spacing on a 4/8 px grid; one table row height; controls at least 32 px high, targets ≥ 24×24 px (WCAG 2.5.8).
- Visible 2 px focus ring; text contrast ≥ 4.5:1; single-key shortcuts can be switched off (WCAG 2.1.4).

## Sources

GOV.UK Design System (button, text input/hint, details), Nielsen Norman Group (progressive disclosure,
help and documentation, toggle guidelines, listbox vs dropdown, confirmation dialogs, tooltips, empty
states), IBM Carbon (button, data table, notification, status indicators, empty states), Microsoft Fluent 2
(button usage), Atlassian Design System (button, lozenge), GitHub Primer (content, progressive disclosure),
WCAG 2.2 (1.4.1, 1.4.3, 1.4.11, 2.1.4, 2.5.8).
