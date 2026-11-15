"""The mechanical rules of the UX concept (docs/ux-concept.md), checked on the static files of the control UI.

The UI is plain HTML and strings of HTML built in JavaScript, so these are text checks: they catch the patterns
the concept bans (emoji as icons, controls inside help, buttons with a selected state, vague labels and link
texts, more than one page title). What needs judgement (one primary button per card, the right verb) is in the
concept and in review."""

import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "control" / "app" / "static"
PAGES = sorted(STATIC.glob("*.html"))
SCRIPTS = sorted(STATIC.glob("*.js"))  # vendor/ is third-party code and not ours to style
SOURCES = PAGES + SCRIPTS
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")

# Symbols the concept allows: ✓ ✕ inside status text, and the typographic marks of the help and controls disclosures.
ALLOWED_SYMBOLS = set("✓✕…·—→▸▾ⓘ")
EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),  # pictographs, emoticons, transport, supplemental symbols
    (0x2600, 0x27BF),  # miscellaneous symbols and dingbats: warning sign, heavy check and cross marks, ...
    (0x2B00, 0x2BFF),  # stars and decorated arrows
    (0x2300, 0x23FF),  # clocks, hourglass, keyboard symbols
    (0xFE0F, 0xFE0F),  # the emoji presentation selector
    (0x20E3, 0x20E3),  # keycap
)
CONTROL = re.compile(r"<(input|select|textarea|button)\b", re.I)
DETAILS = re.compile(r"<details\b[^>]*>|</details>", re.I)


def source_id(path):
    return path.name


def is_emoji(ch):
    return ch not in ALLOWED_SYMBOLS and any(lo <= ord(ch) <= hi for lo, hi in EMOJI_RANGES)


def details_blocks(text):
    """Every <details ...> element in `text` as (opening tag, inner text), nested ones included."""
    stack, out = [], []
    for m in DETAILS.finditer(text):
        if m.group(0).startswith("</"):
            if stack:
                tag, start = stack.pop()
                out.append((tag, text[start : m.start()]))
        else:
            stack.append((m.group(0), m.end()))
    assert not stack, f"unclosed <details>: {stack[0][0]}"
    return out


def has_class(tag, name):
    m = re.search(r'class="([^"]*)"', tag)
    return bool(m) and name in m.group(1).split()


@pytest.mark.parametrize("path", SOURCES, ids=source_id)
def test_no_emoji_as_icons_or_status_markers(path):
    found = sorted({ch for ch in path.read_text(encoding="utf-8") if is_emoji(ch)})
    assert not found, f"{path.name}: use words, the status dot or ✓ ✕ ! instead of {' '.join(found)}"


def test_the_emoji_check_knows_what_it_bans():
    assert all(is_emoji(ch) for ch in "🔑🔒🎉📁⚠✔✖☰⬑⏰")
    assert not any(is_emoji(ch) for ch in "✓✕!…·—→▸▾ⓘ–×“”")


@pytest.mark.parametrize("path", SOURCES, ids=source_id)
def test_help_disclosures_contain_text_only(path):
    """Help never contains controls: those go into <details class="more"> or a <details class="card"> panel."""
    for tag, inner in details_blocks(path.read_text(encoding="utf-8")):
        if has_class(tag, "help"):
            m = CONTROL.search(inner)
            assert not m, f"{path.name}: {tag} contains <{m.group(1)}"


@pytest.mark.parametrize("path", SOURCES, ids=source_id)
def test_every_disclosure_is_help_controls_or_a_content_panel(path):
    for tag, _ in details_blocks(path.read_text(encoding="utf-8")):
        assert any(has_class(tag, c) for c in ("help", "more", "card")), f"{path.name}: {tag}"


def test_a_help_disclosure_ends_with_its_docs_link():
    """A docs link inside help is the last line: nothing but closing tags follows it."""
    for path in SOURCES:
        for tag, inner in details_blocks(path.read_text(encoding="utf-8")):
            if has_class(tag, "help") and "<a " in inner:
                rest = inner[inner.rindex("</a>") + 4 :]
                assert not re.sub(r"</\w+>|\$\{[^}]*\}|[\s`;]", "", rest), f"{path.name}: {tag} text after its link"


def test_no_button_shows_a_selected_state():
    assert "aria-pressed" not in INDEX
    for path in SCRIPTS + sorted(STATIC.glob("*.css")):
        assert "aria-pressed" not in path.read_text(encoding="utf-8"), path.name


@pytest.mark.parametrize("path", SOURCES, ids=source_id)
def test_no_vague_button_labels(path):
    text = path.read_text(encoding="utf-8")
    banned = r"(OK|Ok|Okay|Store|Submit|Go|Click here)"
    for pattern in (rf"<button\b[^>]*>\s*{banned}\s*</button>", rf'textContent\s*=\s*["\'`]{banned}["\'`]'):
        m = re.search(pattern, text)
        assert not m, f"{path.name}: a button label is verb + noun, not {m.group(0)!r}"


@pytest.mark.parametrize("path", SOURCES, ids=source_id)
def test_button_labels_in_markup_are_sentence_case(path):
    for m in re.finditer(r"<button\b[^>]*>([^<$]+)</button>", path.read_text(encoding="utf-8")):
        label = m.group(1).strip()
        if not label or not label[0].isalpha():
            continue
        assert label[0].isupper(), f"{path.name}: {label!r} starts in lower case"
        assert not re.search(r"[.!]$", label), f"{path.name}: {label!r} ends with punctuation"
        words = label.split()[1:]
        titled = [
            w for w in words if w[0].isupper() and w not in ("Remote", "Control", "CSV", "JSON", "GitHub", "Setup")
        ]
        assert not titled, f"{path.name}: {label!r} is not sentence case"


@pytest.mark.parametrize("path", SOURCES, ids=source_id)
def test_no_bare_link_texts(path):
    m = re.search(r">\s*(here|how|more|click here|this|link)\s*</a>", path.read_text(encoding="utf-8"), re.I)
    assert not m, f"{path.name}: a link text says where it leads, not {m.group(0)!r}"


def test_docs_links_live_in_help_not_on_the_surface():
    """A link to the documentation is the last line of a help disclosure, never inline in a hint."""
    for path in SOURCES:
        text = path.read_text(encoding="utf-8")
        in_help = "".join(inner for tag, inner in details_blocks(text) if has_class(tag, "help"))
        for m in re.finditer(r'href="(https://github\.com/PhilippMundhenk/tallygate/blob/[^"]*)"', text):
            assert m.group(1) in in_help, f"{path.name}: docs link outside help: {m.group(1)}"
    for m in re.finditer(r'<p class="hint"[^>]*>(.*?)</p>', INDEX, re.S):
        assert "<a " not in m.group(1), f"hint with a link: {m.group(1)[:60]}"


def test_each_tab_has_exactly_one_page_title():
    tabs = re.findall(r'<section id="(tab-[a-z]+)"[^>]*>(.*?)</section>', INDEX, re.S)
    menu = re.findall(r'<button data-tab="([a-z]+)"', INDEX)
    assert {name for name, _ in tabs} == {f"tab-{t}" for t in menu} and len(tabs) == 10
    for name, body in tabs:
        assert len(re.findall(r"<h2\b", body)) == 1, f"{name}: one <h2> page title per tab"
        assert re.search(r"<h2\b", body).start() < 20, f"{name}: the title comes first"
        assert not re.search(r"<h1\b", body), name
    # sections built in JavaScript are sections of a tab: h3 and below
    for path in SCRIPTS:
        assert not re.search(r"<h[12]\b", path.read_text(encoding="utf-8")), f"{path.name}: use h3/h4 inside a tab"


def test_no_card_is_written_inside_a_card():
    """Static markup only: a .card element never contains another .card."""
    depth_at_card = []
    depth = 0
    for m in re.finditer(r"<(div|details|section)\b([^>]*)>|</(div|details|section)>", INDEX):
        if m.group(3):
            depth -= 1
            if depth_at_card and depth_at_card[-1] == depth:
                depth_at_card.pop()
            continue
        cls = re.search(r'class="([^"]*)"', m.group(2))
        if cls and "card" in cls.group(1).split():
            assert not depth_at_card, f"card inside a card: {m.group(0)}"
            depth_at_card.append(depth)
        depth += 1
    assert depth == 0


def test_the_stylesheet_has_the_shared_vocabulary():
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    for rule in ("button.ghost{", "button.secondary{", "button.danger{", ".status{", ".status::before{", ".alert{"):
        assert rule in css, rule
    for state in ("ok", "warn", "bad", "off"):
        assert f".status.{state}{{" in css, state
    assert "details.help" in css and "details.more" in css
    # type scale 20/15/13/12 px, in every stylesheet of the UI
    for path in sorted(STATIC.glob("*.css")):
        if path.name == "term.css":
            continue  # the console page: a terminal, not a page of the UI
        sizes = set(re.findall(r"font-size:([\d.]+px)", path.read_text(encoding="utf-8")))
        assert sizes <= {"20px", "15px", "13px", "12px"}, f"{path.name}: {sorted(sizes)}"
    assert "min-height:32px" in css and "outline:2px solid" in css  # control height and the focus ring
