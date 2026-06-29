# visuals.py
# IoT Security Scanner - Visual Generation Engine
# Produces two PNG images that get embedded into the PDF report:
#   1. Network Topology Map  — devices as coloured nodes around the router
#   2. Risk Trend Graph      — network score over the last 10 scans

import os
import tempfile

# ── Colour palette ────────────────────────────────────────────────────────────
ROUTER_COLOR = '#0078D7'   # Blue — used in trend graph line colour
BACKGROUND   = '#F8F8F8'
TEXT_COLOR   = '#1A1A1A'


# ===========================================================================
# 1.  Risk Trend Graph
# ===========================================================================

def generate_trend_graph(db_path: str) -> str | None:
    """
    Reads the last 10 scans from the SQLite history database and plots
    the network security score over time as a line chart.

    Args:
        db_path : absolute path to scanner_history.db

    Returns:
        str  : path to saved PNG
        None : if fewer than 2 scans exist (not enough data to trend)
    """
    import sqlite3
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker

    # ── Pull data from DB ──────────────────────────────────────────────────────
    if not os.path.exists(db_path):
        return None

    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            """SELECT timestamp, score, score_label
               FROM scans
               ORDER BY id DESC
               LIMIT 10"""
        ).fetchall()
        conn.close()
    except Exception:
        return None

    if len(rows) < 2:
        return None

    # Reverse so oldest scan is on the left
    rows      = list(reversed(rows))
    labels    = [r[0][5:16] for r in rows]   # "MM-DD HH:MM"
    scores    = [r[1]       for r in rows]

    # ── Plot ──────────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, 4.5))
    fig.patch.set_facecolor(BACKGROUND)
    ax.set_facecolor(BACKGROUND)

    # Shaded risk zones
    ax.axhspan(0,  50,  alpha=0.08, color='#DC3232', label='Critical zone')
    ax.axhspan(50, 70,  alpha=0.08, color='#FF7800', label='At Risk zone')
    ax.axhspan(70, 90,  alpha=0.08, color='#FFC800', label='Good zone')
    ax.axhspan(90, 100, alpha=0.08, color='#32B432', label='Excellent zone')

    # Score line
    ax.plot(labels, scores,
            color     = ROUTER_COLOR,
            linewidth = 2.5,
            marker    = 'o',
            markersize= 7,
            zorder    = 3,
            label     = 'Network Score')

    # Colour each point by its score
    for i, (lbl, score) in enumerate(zip(labels, scores)):
        color = ('#DC3232' if score < 50  else
                 '#FF7800' if score < 70  else
                 '#FFC800' if score < 90  else
                 '#32B432')
        ax.plot(lbl, score, 'o', color=color, markersize=9, zorder=4)
        ax.annotate(
            str(score),
            xy         = (lbl, score),
            xytext     = (0, 10),
            textcoords = 'offset points',
            ha         = 'center',
            fontsize   = 8,
            color      = TEXT_COLOR,
        )

    # Axes styling
    ax.set_ylim(0, 105)
    ax.set_ylabel('Network Score', fontsize=10, color=TEXT_COLOR)
    ax.set_xlabel('Scan Timestamp', fontsize=10, color=TEXT_COLOR)
    ax.set_title('Network Security Score — Historical Trend',
                 fontsize=13, fontweight='bold', color=TEXT_COLOR, pad=10)

    ax.tick_params(axis='x', rotation=30, labelsize=7.5, colors=TEXT_COLOR)
    ax.tick_params(axis='y', labelsize=8,  colors=TEXT_COLOR)
    ax.yaxis.set_major_locator(ticker.MultipleLocator(10))

    # Horizontal reference lines
    for level, label_text, color in [
        (50, 'Critical', '#DC3232'),
        (70, 'At Risk',  '#FF7800'),
        (90, 'Good',     '#32B432'),
    ]:
        ax.axhline(level, color=color, linewidth=0.8,
                   linestyle='--', alpha=0.6)
        ax.text(0.01, level + 1, label_text,
                transform    = ax.get_yaxis_transform(),
                fontsize     = 7,
                color        = color,
                alpha        = 0.8)

    ax.grid(axis='y', linestyle=':', alpha=0.4, color='#AAAAAA')
    ax.legend(loc='upper right', fontsize=8, framealpha=0.9)

    for spine in ax.spines.values():
        spine.set_edgecolor('#DDDDDD')

    plt.tight_layout()

    # ── Save ──────────────────────────────────────────────────────────────────
    tmp = tempfile.NamedTemporaryFile(
        suffix = '_trend.png',
        delete = False,
        prefix = 'iot_scanner_'
    )
    fig.savefig(tmp.name, dpi=130, bbox_inches='tight',
                facecolor=BACKGROUND)
    plt.close(fig)

    return tmp.name


# ===========================================================================
# 2.  Cleanup Helper
# ===========================================================================

def cleanup_images(*paths: str) -> None:
    """Deletes temporary PNG files after they've been embedded in the PDF."""
    for path in paths:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
