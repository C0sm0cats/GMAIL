"""Render the picker with demo emails into docs/screenshot.svg (the README screenshot).

Run from the repository root:  .venv/bin/python -m pip install pyte && .venv/bin/python docs/make_screenshot.py
It draws the real list into a virtual terminal (pyte), then turns that screen into an SVG.
"""
import io
import os
import sys
import threading
import time
from html import escape

import pyte
from prompt_toolkit.application import create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output.vt100 import Vt100_Output

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import savegmail  # noqa: E402

COLUMNS, ROWS = 140, 17
OUT = os.path.join(ROOT, "docs", "screenshot.svg")

# One Dark-like palette for pyte's color names.
PALETTE = {
    "default": "#d7dae0", "black": "#282c34", "red": "#e06c75", "green": "#98c379", "brown": "#e5c07b",
    "yellow": "#e5c07b", "blue": "#61afef", "magenta": "#c678dd", "cyan": "#56b6c2", "white": "#d7dae0",
    "brightblack": "#7f848e", "brightred": "#ff7b86", "brightgreen": "#b5e890", "brightyellow": "#f0d58a",
    "brightblue": "#82c4ff", "brightmagenta": "#de9cf0", "brightcyan": "#7fd3dd", "brightwhite": "#ffffff",
}
BACKGROUND, CELL_W, CELL_H, FONT = "#1e2127", 8.6, 19, 14.2


def color(name, default):
    if name == "default":
        return default
    return PALETTE.get(name, f"#{name}" if len(name) == 6 else default)


def demo_messages():
    now = int(time.time() * 1000)
    hour, day = 3_600_000, 86_400_000

    def email(i, ago, sender, subject, snippet, labels, size, attachment=False, to=""):
        return {"id": str(i), "internalDate": now - ago, "from": sender, "to": to, "subject": subject,
                "snippet": snippet, "labels": labels, "size": size, "attachment": attachment}

    return [
        email(0, 1 * hour, "Acme Energy <billing@acme.example>", "Your October invoice",
              "Your invoice is ready: view or download it from your account", ["INBOX", "UNREAD", "STARRED",
              "Label_1", "CATEGORY_UPDATES"], 2_400_000, attachment=True),
        email(1, 3 * hour, "Paul Martin <paul@example.com>", "Weekend photos", "Here are the photos from Saturday",
              ["SENT"], 12_800_000, attachment=True, to="Paul Martin <paul@example.com>"),
        email(2, 5 * hour, "you@gmail.com", "Re: roofing quote", "OK for Thursday, I'll come by around 10",
              ["DRAFT"], 18_000),
        email(3, 2 * day, "GitHub <noreply@github.com>", "[gmail] PR #42 merged", "Merged #42 into main",
              ["INBOX", "UNREAD", "CATEGORY_UPDATES"], 41_000),
        email(4, 9 * day, "LinkedIn <news@linkedin.example>", "Davy shared a post",
              "Last Tuesday was my first event of the season", ["CATEGORY_SOCIAL", "Label_3"], 154_000),
        email(5, 20 * day, "SkyAir <booking@skyair.example>", "Your boarding pass", "Flight SA 312, gate opens at",
              ["INBOX", "Label_2"], 820_000, attachment=True),
        email(6, 400 * day, "Shop Deals <deals@shop.example>", "Last chance: 40% off everything",
              "Our biggest sale ends tonight", ["CATEGORY_PROMOTIONS"], 64_000),
    ]


def render_screen():
    savegmail.ACCOUNT = "you@gmail.com"
    savegmail.USER_LABELS = {"Label_1": "Invoices", "Label_2": "Travel", "Label_3": "Social/LinkedIn"}
    messages = demo_messages()
    state = savegmail.new_picker_state()
    state["selected"] = {"0", "3"}
    state["cursor"] = 1
    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(rows=ROWS, columns=COLUMNS), term="xterm-256color")
    snapshot = []
    with create_pipe_input() as pipe:
        with create_app_session(input=pipe, output=output):
            def capture():
                time.sleep(0.6)
                snapshot.append(buffer.getvalue())
                pipe.send_text("\x03")
            threading.Thread(target=capture, daemon=True).start()
            savegmail.pick_messages(
                messages, load_more=lambda: ([], False), state=state, undo_label="archive (1)", total=1240,
                views=[name for name, _ in savegmail.VIEWS], view=0, folder="~/GMail/",
                badges={"All mail": ("15", "unread"), "Inbox": ("12", "unread"), "Archived": ("3", "unread"),
                        "Starred": ("2", "unread"), "Drafts": ("1", "total")},
            )
    screen = pyte.Screen(COLUMNS, ROWS)
    pyte.Stream(screen).feed(snapshot[0])
    return screen


def banner_cells():
    """The line savegmail prints above the list, as (char, fg, bold) cells."""
    parts = [(" savegmail", "default", True), ("  ·  ", "brightblack", False), ("you@gmail.com", "default", False),
             ("  ·  query: ", "brightblack", False), ("(all)", "brightblack", False),
             ("  ·  → ", "brightblack", False), ("~/GMail/", "default", False)]
    return [(char, fg, bold) for text, fg, bold in parts for char in text]


def svg(screen):
    pad_x, pad_top, title_h = 18, 16, 34
    lines = [banner_cells(), []]  # banner, blank line
    for y in range(ROWS):
        row = screen.buffer[y]
        cells = []
        for x in range(COLUMNS):
            cell = row[x]
            cells.append((cell.data, cell.fg, cell.bold, cell.bg, cell.reverse))
        lines.append(cells)
    while lines and not any(cell[0].strip() for cell in lines[-1]):
        lines.pop()

    width = pad_x * 2 + COLUMNS * CELL_W
    height = title_h + pad_top * 2 + len(lines) * CELL_H
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
           f'viewBox="0 0 {width:.0f} {height:.0f}" font-family="\'JetBrains Mono\', \'DejaVu Sans Mono\', Menlo, '
           f'Consolas, monospace" font-size="{FONT}">',
           f'<rect width="100%" height="100%" rx="10" fill="{BACKGROUND}"/>',
           f'<rect width="100%" height="{title_h}" rx="10" fill="#2c313a"/>',
           f'<rect y="{title_h - 10}" width="100%" height="10" fill="#2c313a"/>']
    for i, dot in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append(f'<circle cx="{20 + i * 20}" cy="{title_h / 2}" r="6" fill="{dot}"/>')
    out.append(f'<text x="{width / 2:.0f}" y="{title_h / 2 + 5}" fill="#9da5b4" text-anchor="middle" '
               f'font-size="13">savegmail</text>')

    for y, cells in enumerate(lines):
        top = title_h + pad_top + y * CELL_H
        baseline = top + CELL_H * 0.75
        x = 0
        while x < len(cells):
            cell = cells[x]
            char, fg, bold = cell[0], cell[1], cell[2]
            bg, reverse = (cell[3], cell[4]) if len(cell) > 3 else ("default", False)
            fill, back = color(fg, PALETTE["default"]), color(bg, None)
            if reverse:
                fill, back = color(bg, BACKGROUND), color(fg, PALETTE["default"])
            # Wide characters (emoji) take two cells: pyte leaves the second one empty.
            wide = x + 1 < len(cells) and cells[x + 1][0] == "" and char not in ("", " ")
            span = 2 if wide else 1
            left = pad_x + x * CELL_W
            if back:
                out.append(f'<rect x="{left:.1f}" y="{top:.1f}" width="{CELL_W * span:.1f}" height="{CELL_H}" '
                           f'fill="{back}"/>')
            if char.strip():
                weight = ' font-weight="bold"' if bold else ""
                if wide:  # emoji: let the viewer's emoji font draw it
                    weight += ' font-family="\'Noto Color Emoji\', \'Apple Color Emoji\', \'Segoe UI Emoji\', sans-serif"'
                out.append(f'<text x="{left + CELL_W * span / 2:.1f}" y="{baseline:.1f}" fill="{fill}"'
                           f'{weight} text-anchor="middle">{escape(char)}</text>')
            x += span
    out.append("</svg>")
    return "\n".join(out)


if __name__ == "__main__":
    with open(OUT, "w") as file:
        file.write(svg(render_screen()))
    print(f"wrote {os.path.relpath(OUT, ROOT)}")
