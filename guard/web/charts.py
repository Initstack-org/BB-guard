"""Server-rendered SVG bar charts for the traffic pages.

No JavaScript and no inline styles (the page CSP forbids both): the SVG uses only presentation
attributes and CSS classes from static/traffic.css. Every piece of text that reaches the SVG is
HTML-escaped, and the numbers are formatted here, so the result is safe to mark as trusted markup.
"""

from __future__ import annotations

import math
from html import escape
from typing import Callable, Sequence

WIDTH = 640
HEIGHT = 200
LEFT, RIGHT, TOP, BOTTOM = 8, 8, 28, 28
MAX_LABELS = 8


def bar_chart(title: str, points: Sequence[tuple[str, str, int]], *, value_text: Callable[[int], str],
              note: str = "") -> str:
    """One bar per (axis label, tooltip label, value). `note` is a short line under the title (units,
    time zone). Returns an <svg> string."""
    n = len(points)
    plot_w = WIDTH - LEFT - RIGHT
    plot_h = HEIGHT - TOP - BOTTOM
    peak = max((v for _, _, v in points), default=0)
    parts = [f'<svg class="chart" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" '
             f'aria-label="{escape(title, quote=True)}" xmlns="http://www.w3.org/2000/svg">',
             f"<title>{escape(title)}</title>",
             f'<text class="chart-title" x="{LEFT}" y="14">{escape(title)}</text>']
    if note:
        parts.append(f'<text class="chart-axis" x="{WIDTH - RIGHT}" y="14" text-anchor="end">{escape(note)}</text>')
    parts.append(f'<text class="chart-axis" x="{LEFT}" y="{TOP - 4}">peak {escape(value_text(peak))}</text>')
    base_y = TOP + plot_h
    parts.append(f'<line class="chart-base" x1="{LEFT}" y1="{base_y}" x2="{WIDTH - RIGHT}" y2="{base_y}"/>')
    if n:
        slot = plot_w / n
        bar_w = max(1.0, slot * 0.8)
        step = max(1, math.ceil(n / MAX_LABELS))
        for i, (label, full, value) in enumerate(points):
            height = 0.0 if peak <= 0 else value / peak * plot_h
            x = LEFT + i * slot + (slot - bar_w) / 2
            parts.append(
                f'<rect class="chart-bar" x="{x:.2f}" y="{base_y - height:.2f}" width="{bar_w:.2f}" '
                f'height="{height:.2f}"><title>{escape(full)}: {escape(value_text(value))}</title></rect>')
            if i % step == 0:
                parts.append(f'<text class="chart-axis" x="{x + bar_w / 2:.2f}" y="{HEIGHT - 10}" '
                             f'text-anchor="middle">{escape(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)
