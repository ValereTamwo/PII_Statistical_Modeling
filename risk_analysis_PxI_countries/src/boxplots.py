"""
DISTRIBUTION VISUALIZATION SUITE - country extension.

Adapted from risk_analysis_PxI/src/boxplots.py: identical F1 rendering
(Pi/Ii/Ri boxplots by storage type, with item-count line overlay), reads
data/user_countries/ for the 6 new-country personas (AUTH/NOTAUTH naming).

The FR version's F2 (Ri by consent policy, per storage) and F3 (Ri by
consent policy, all storages) are dropped: country data was collected
under a single PARTIAL policy only, so there is nothing to compare on
that axis - same reasoning already applied to the GDPR report's dropped
"Consent Policy Impact" section and analysis_countries' storage/cookie
pipelines.

Additions vs. the FR version (which only ever renders one pooled F1 for a
single hardcoded mode/policy example):
- F1 pooled per AUTH/NOTAUTH (2 figures) AND per country per AUTH/NOTAUTH
  (12 figures), since the whole point of the country extension is
  comparing countries against each other.
- A new F2: Ri distribution across the 6 countries, AUTH vs NOTAUTH
  (all storage types pooled per country) - the FR pipeline has no
  country axis to plot this against, so there is no equivalent figure
  to adapt from; this one is new.
"""

import json
import sys
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import FuncFormatter

from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from countries_config import add_users_arg, resolve_users

matplotlib.rcParams.update({
    'font.family':        'serif',
    'font.size':          8,
    'axes.labelsize':     14,
    'axes.titlesize':     8,
    'axes.titleweight':   'normal',
    'xtick.labelsize':    12,
    'ytick.labelsize':    12,
    'legend.fontsize':    12,
    'legend.framealpha':  1.0,
    'legend.edgecolor':   '#aaaaaa',
    'legend.borderpad':   0.4,
    'axes.linewidth':     0.6,
    'xtick.major.width':  0.6,
    'ytick.major.width':  0.6,
    'xtick.major.size':   3,
    'ytick.major.size':   3,
    'xtick.direction':    'in',
    'ytick.direction':    'in',
    'axes.spines.top':    False,
    'grid.alpha':         0.35,
    'grid.linewidth':     0.4,
    'grid.color':         '#bbbbbb',
    'patch.linewidth':    0.5,
    'savefig.dpi':        300,
    'savefig.bbox':       'tight',
    'savefig.pad_inches': 0.03,
})

STORAGES      = ['cookie', 'localStorage', 'sessionStorage', 'IndexedDB']
STORAGE_SHORT = ['Cookie', 'LS', 'SS', 'IDB']
POLICIES      = ['PARTIAL']
MODES         = ['AUTH', 'NOTAUTH']

METRIC_COLORS  = {'Pi': '#4472C4', 'Ii': '#70AD47', 'Ri': '#C00000'}
METRIC_HATCHES = {'Pi': '',        'Ii': '//',       'Ri': 'xx'     }

MODE_COLORS    = {'AUTH': '#4472C4', 'NOTAUTH': '#C00000'}
MODE_HATCHES   = {'AUTH': '',        'NOTAUTH': '//'     }

COUNT_COLOR    = "#636161"


def load_items(data_root: Path, mode: str, policy: str,
               user: str = None) -> list:
    """
    Loads risk score vectors. If user is None, aggregates across all countries.
    """
    if user is not None:
        path = (data_root / "user_countries" / mode / user / policy
                / "_vector_data" / "vectorized_items_risk_score.json")
        if not path.exists():
            raise FileNotFoundError(f"Not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    all_items = []
    user_dir  = data_root / "user_countries" / mode
    if not user_dir.exists():
        raise FileNotFoundError(f"Not found: {user_dir}")
    for user_folder in sorted(user_dir.iterdir()):
        if not user_folder.is_dir():
            continue
        path = (user_folder / policy / "_vector_data"
                / "vectorized_items_risk_score.json")
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                all_items.extend(json.load(f))
        else:
            print(f"  Warning: missing {user_folder.name}/{policy}")
    return all_items

def format_k(x, pos):
    if x >= 1000:
        return f'{x/1000:.1f}k'.replace('.0', '')
    return f'{int(x)}'


def _render(
    ax, ax_r,
    group_labels: list,
    series: list,
    counts: list,
    group_w=0.72, box_ratio=0.80,
    x_label_rotation=0
):
    """
    Core rendering engine: Overlays grouped boxplots with frequency line plots.
    """
    n_groups  = len(group_labels)
    n_series  = len(series)
    box_w     = group_w / n_series
    offsets   = np.linspace(-(n_series-1)/2, (n_series-1)/2, n_series) * box_w

    bp_handles = []
    for si, s in enumerate(series):
        col  = s['color']
        htch = s['hatch']
        for gi, data in enumerate(s['data_per_group']):
            if not data:
                continue
            pos = gi + offsets[si]
            bp  = ax.boxplot(
                data,
                positions    = [pos],
                widths       = box_w * box_ratio,
                patch_artist = True,
                notch        = False,
                showfliers   = False,
                whis         = (0, 100),
                medianprops  = dict(color='black', linewidth=1.5),
                boxprops     = dict(facecolor=col, alpha=0.75, linewidth=0.6),
                whiskerprops = dict(linewidth=0.8, linestyle='-'),
                capprops     = dict(linewidth=1.0),
            )
            for patch in bp['boxes']:
                patch.set_hatch(htch)
                patch.set_edgecolor('black')

        bp_handles.append(mpatches.Patch(
            facecolor=col, hatch=htch,
            edgecolor='black', linewidth=0.5,
            label=s['label']
        ))

    for sep in [gi + 0.5 for gi in range(n_groups - 1)]:
        ax.axvline(sep, color='#cccccc', lw=0.5, zorder=0)

    ax.set_xticks(np.arange(n_groups))
    # ax.set_xticklabels(group_labels)
    ax.set_xticklabels(
    group_labels,
    rotation=x_label_rotation,
    ha='right' if x_label_rotation else 'center'
)
    ax.set_xlim(-0.55, n_groups - 0.45)
    ax.set_ylabel('Score [0, 1]')
    ax.set_ylim(-0.05, 1.15)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines['right'].set_visible(True)

    x_c = np.arange(n_groups)
    ax_r.plot(x_c, counts,
              color=COUNT_COLOR, lw=1.2, ls='-',
              marker='D', markersize=4,
              markerfacecolor='white', markeredgecolor=COUNT_COLOR,
              markeredgewidth=0.8, zorder=5)
    offset = 0.08 * max(counts) if counts and max(counts) > 0 else 0.1
    for xi, cnt in zip(x_c, counts):
        ax_r.text(xi, cnt + offset, str(cnt),
                  ha='center', va='top', fontsize=10, color=COUNT_COLOR,
                  bbox=dict(boxstyle='round,pad=0.1', fc='white', ec='none', alpha=0.8))
    ax_r.set_ylabel('# Items', color=COUNT_COLOR)
    ax_r.tick_params(axis='y', labelcolor=COUNT_COLOR,
                     direction='in', width=0.6, size=3)
    ax_r.spines['top'].set_visible(False)
    ax_r.yaxis.set_major_formatter(FuncFormatter(format_k))
    ax_r.set_ylim(0, max(counts) * 1.35 if counts and max(counts) > 0 else 1)

    count_handle = plt.Line2D(
        [0], [0], color=COUNT_COLOR, lw=1.2, ls='-',
        marker='D', markersize=4,
        markerfacecolor='white', markeredgecolor=COUNT_COLOR,
        markeredgewidth=0.8, label='$n$ items'
    )
    ax.legend(
        handles=bp_handles + [count_handle],
        loc='upper left', ncol=n_series + 1,
        handlelength=1.2, handleheight=0.9,
        columnspacing=0.7, borderpad=0.4,
        bbox_to_anchor=(0, 1.05),
    )


def _save(fig, output_dir: Path, stem: str):
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / f"{stem}.pdf")
    fig.savefig(output_dir / f"{stem}.png")
    plt.close(fig)
    print(f"  Saved: {stem}.pdf / .png")


# ============================================================
# F1 - Pi / Ii / Ri by storage (one fixed context per figure)
# ============================================================

def plot_f1_metrics_by_storage(data_root: Path, output_dir: Path,
                                mode: str, policy: str, user: str = None):
    """
    X-axis  : Cookie | LS | SS | IDB
    Boxplots: Pi  Ii  Ri
    """
    items  = load_items(data_root, mode=mode, policy=policy, user=user)
    groups = defaultdict(list)
    for it in items:
        groups[it.get('storage_type','?')].append(it)

    series = [
        {'label': r'$P_i$', 'color': METRIC_COLORS['Pi'],
         'hatch': METRIC_HATCHES['Pi'],
         'data_per_group': [
             [it.get('pi_exposure', 0.) for it in groups.get(s, [])]
             for s in STORAGES]},
        {'label': r'$I_i$', 'color': METRIC_COLORS['Ii'],
         'hatch': METRIC_HATCHES['Ii'],
         'data_per_group': [
             [it.get('ii_impact', 0.) for it in groups.get(s, [])]
             for s in STORAGES]},
        {'label': r'$R_i$', 'color': METRIC_COLORS['Ri'],
         'hatch': METRIC_HATCHES['Ri'],
         'data_per_group': [
             [it.get('risk_i', 0.) for it in groups.get(s, [])]
             for s in STORAGES]},
    ]
    counts = [len(groups.get(s, [])) for s in STORAGES]

    fig, ax = plt.subplots(figsize=(7.0, 3.0))
    ax_r    = ax.twinx()
    _render(ax, ax_r, STORAGE_SHORT, series, counts)

    u_label = user if user else 'all'
    stem    = f"f1_metrics_by_storage_{mode}_{u_label}_{policy}"
    _save(fig, output_dir, stem)


# ============================================================
# F2 - Risk (Ri) distribution across the 6 countries, seen
# through the AUTH vs NOTAUTH lens (single PARTIAL policy, all
# storage types pooled per country)
# ============================================================

def plot_risk_by_country_and_mode(data_root: Path, output_dir: Path, policy: str, users: list):
    """
    X-axis  : the countries in `users`
    Boxplots: Ri^AUTH  Ri^NOTAUTH  (all storage types pooled)
    """
    series = []
    counts_per_country = []

    for mode in MODES:
        data_per_country = []
        for user in users:
            items = load_items(data_root, mode=mode, policy=policy, user=user)
            vals  = [it.get('risk_i', 0.) for it in items]
            data_per_country.append(vals)
        series.append({
            'label': f'$R_i^{{\\mathrm{{{mode}}}}}$',
            'color': MODE_COLORS[mode],
            'hatch': MODE_HATCHES[mode],
            'data_per_group': data_per_country,
        })

    for user in users:
        n = sum(len(load_items(data_root, mode=m, policy=policy, user=user)) for m in MODES)
        counts_per_country.append(n)

    fig, ax = plt.subplots(figsize=(9.0, 3.4))
    ax_r    = ax.twinx()
    _render(ax, ax_r, [u.split('_')[0] for u in users], series, counts_per_country,x_label_rotation=0)
    ax.set_title(f"Risk score ($R_i$) distribution by country - AUTH vs NOTAUTH ({"Essential Only"} policy)")

    _save(fig, output_dir, "f2_risk_by_country_and_mode")


def main(users=None):
    base_dir   = Path(__file__).resolve().parents[2]
    data_root  = base_dir / "data"
    output_dir = Path(__file__).resolve().parent / "outputs" / "figures"

    users = users or resolve_users(None)

    print("=" * 55)
    print("  ITEM-LEVEL BOXPLOT SUITE - country extension")
    print("=" * 55)
    print(f"Scoped to users: {users}")

    policy = POLICIES[0]

    print("\n  [F1] Pi/Ii/Ri by storage - pooled across all countries, per auth mode")
    for mode in MODES:
        plot_f1_metrics_by_storage(data_root, output_dir, mode=mode, policy=policy)

    print("\n  [F1] Pi/Ii/Ri by storage - per country, per auth mode")
    for mode in MODES:
        for user in users:
            try:
                plot_f1_metrics_by_storage(data_root, output_dir, mode=mode, policy=policy, user=user)
            except FileNotFoundError as e:
                print(f"  [SKIP] {e}")

    print("\n  [F2] Risk (Ri) distribution by country - AUTH vs NOTAUTH")
    plot_risk_by_country_and_mode(data_root, output_dir, policy=policy, users=users)

    print("\n" + "=" * 55)
    print("  Done.")
    print("=" * 55)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    add_users_arg(parser)
    args = parser.parse_args()
    main(users=resolve_users(args.users))
