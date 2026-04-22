"""
DISTRIBUTION VISUALIZATION SUITE
Generates item-level boxplots accompanied by item count overlays.
Figures:
  F1: Risk metrics (Pi/Ii/Ri) by storage API.
  F2: Policy impact on risk score (Ri) per storage.
  F3: Global policy impact (multi-storage).
"""

import json
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import FuncFormatter

from pathlib import Path
from collections import defaultdict

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
POLICIES      = ['ALL', 'PARTIAL', 'NONE']
MODES         = ['Auth', 'UnAuth']

METRIC_COLORS  = {'Pi': '#4472C4', 'Ii': '#70AD47', 'Ri': '#C00000'}
METRIC_HATCHES = {'Pi': '',        'Ii': '//',       'Ri': 'xx'     }

MODE_COLORS    = {'Auth': '#4472C4', 'UnAuth': '#C00000'}
MODE_HATCHES   = {'Auth': '',        'UnAuth': '//'     }

COUNT_COLOR    = "#636161"


def load_items(data_root: Path, mode: str, policy: str,
               user: str = None) -> list:
    """
    Loads risk score vectors. If user is None, aggregates across all profiles.
    """
    if user is not None:
        path = (data_root / "user" / mode / user / policy
                / "_vector_data" / "vectorized_items_risk_score.json")
        if not path.exists():
            raise FileNotFoundError(f"Not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    all_items = []
    user_dir  = data_root / "user" / mode
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


def load_items_multi(data_root: Path, mode: str, policies: list,
                     storage_filter: str = None) -> dict:
    """
    Retourne {policy: [items]} pour un mode donné.
    Filtre optionnel par storage_type.
    """
    result = {}
    for policy in policies:
        items = load_items(data_root, mode=mode, policy=policy)
        if storage_filter:
            items = [it for it in items
                     if it.get('storage_type','').lower() == storage_filter.lower()]
        result[policy] = items
    return result




def _render(
    ax, ax_r,
    group_labels: list,        
    series: list,              
    counts: list,              
    group_w=0.72, box_ratio=0.80
):
    """
    Core rendering engine: Overlays grouped boxplots with frequency line plots.
    """
    n_groups  = len(group_labels)
    n_series  = len(series)
    # group_w   = 0.72
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
                showfliers   = False,          # Exclude outliers for visual clarity
                whis         = (0, 100),       # Whiskers encompass the full range
                medianprops  = dict(color='black', linewidth=1.5),
                boxprops     = dict(facecolor=col, alpha=0.75, linewidth=0.6),
                whiskerprops = dict(linewidth=0.8, linestyle='-'),  # ligne pleine
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

    # Structural separators
    for sep in [gi + 0.5 for gi in range(n_groups - 1)]:
        ax.axvline(sep, color='#cccccc', lw=0.5, zorder=0)

    ax.set_xticks(np.arange(n_groups))
    ax.set_xticklabels(group_labels)
    ax.set_xlim(-0.55, n_groups - 0.45)
    ax.set_ylabel('Score [0, 1]')
    ax.set_ylim(-0.05, 1.15)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines['right'].set_visible(True)

    # Lineplot count    
    x_c = np.arange(n_groups)
    ax_r.plot(x_c, counts,
              color=COUNT_COLOR, lw=1.2, ls='-',
              marker='D', markersize=4,
              markerfacecolor='white', markeredgecolor=COUNT_COLOR,
              markeredgewidth=0.8, zorder=5)
    offset = 0.08 * max(counts)
    for xi, cnt in zip(x_c, counts):
        ax_r.text(xi, cnt + offset, str(cnt),
                  ha='center', va='top', fontsize=10, color=COUNT_COLOR,
                  bbox=dict(boxstyle='round,pad=0.1', fc='white', ec='none', alpha=0.8))
    ax_r.set_ylabel('# Items', color=COUNT_COLOR)
    ax_r.tick_params(axis='y', labelcolor=COUNT_COLOR,
                     direction='in', width=0.6, size=3)
    ax_r.spines['top'].set_visible(False)
    ax_r.yaxis.set_major_formatter(FuncFormatter(format_k))
    ax_r.set_ylim(0, max(counts) * 1.35 if counts else 1)

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


# ════════════════════════════════════════════════════════════
# F1 — Pi / Ii / Ri par storage  (1 contexte fixe)
# ════════════════════════════════════════════════════════════

def plot_f1_metrics_by_storage(data_root: Path, output_dir: Path,
                                mode: str, policy: str, user: str = None):
    """
    Abscisses : Cookie | LS | SS | IDB
    Boxplots  : Pi  Ii  Ri
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


# ════════════════════════════════════════════════════════════
# F2 — Ri_Auth / Ri_UnAuth par policy, par storage (4 figures)
# ════════════════════════════════════════════════════════════

# def plot_f2_modes_by_policy_per_storage(data_root: Path, output_dir: Path):
#     """
#     Une figure par storage type.
#     Abscisses : ALL | PARTIAL | NONE
#     Boxplots  : Ri_Auth  Ri_UnAuth
#     """
#     for st, st_short in zip(STORAGES, STORAGE_SHORT):
#         series = []
#         counts = []

#         for mode in MODES:
#             data_per_policy = []
#             for policy in POLICIES:
#                 items = load_items(data_root, mode=mode, policy=policy)
#                 vals  = [it.get('risk_i', 0.)
#                          for it in items
#                          if it.get('storage_type','').lower() == st.lower()]
#                 data_per_policy.append(vals)

#             series.append({
#                 'label': f'$R_i^{{\\mathrm{{{mode}}}}}$',
#                 'color': MODE_COLORS[mode],
#                 'hatch': MODE_HATCHES[mode],
#                 'data_per_group': data_per_policy,
#             })

#         # Count = total items (Auth + UnAuth) par policy pour ce storage
#         for policy in POLICIES:
#             n = sum(
#                 len([it for it in load_items(data_root, mode=m, policy=policy)
#                      if it.get('storage_type','').lower() == st.lower()])
#                 for m in MODES
#             )
#             counts.append(n)

#         fig, ax = plt.subplots(figsize=(4.5, 3.0))
#         ax_r    = ax.twinx()
#         _render(ax, ax_r, POLICIES, series, counts)

#         stem = f"f2_modes_by_policy_{st}"
#         _save(fig, output_dir, stem)

def plot_f2_modes_by_policy_per_storage(data_root: Path, output_dir: Path):
  
    for st, st_short in zip(STORAGES, STORAGE_SHORT):
        combined_risks_per_policy = []
        counts_per_policy = []

        for policy in POLICIES:
            items_auth = load_items(data_root, mode='Auth', policy=policy)
            items_unauth = load_items(data_root, mode='UnAuth', policy=policy)
            
            all_items = items_auth + items_unauth
            st_items = [it for it in all_items if it.get('storage_type', '').lower() == st.lower()]
            
            risks = [it.get('risk_i', 0) for it in st_items]
            combined_risks_per_policy.append(risks)
            counts_per_policy.append(len(st_items))

        series = [{
            'label': r'$R_i$ ',
            'data_per_group': combined_risks_per_policy,
            'color': METRIC_COLORS['Ri'],
            'hatch': METRIC_HATCHES['Ri']
        }]

        fig, ax1 = plt.subplots(figsize=(4, 4))
        ax2 = ax1.twinx()
        
        _render(ax1, ax2, POLICIES, series, counts_per_policy)
        stem = f"f2_modes_by_policy_{st}"
        # ax1.set_title(f"Risk Score: {st_short}")
        _save(fig, output_dir, stem)





def plot_f3_modes_by_policy_all_storages(data_root: Path, output_dir: Path):
    """
    Abscisses : ALL | PARTIAL | NONE
    Boxplots  : Ri_Auth  Ri_UnAuth  (tous storages confondus)
    """
    series = []
    counts = []

    for mode in MODES:
        data_per_policy = []
        for policy in POLICIES:
            items = load_items(data_root, mode=mode, policy=policy)
            vals  = [it.get('risk_i', 0.) for it in items]
            data_per_policy.append(vals)
        series.append({
            'label': f'$R_i^{{\\mathrm{{{mode}}}}}$',
            'color': MODE_COLORS[mode],
            'hatch': MODE_HATCHES[mode],
            'data_per_group': data_per_policy,
        })

    for policy in POLICIES:
        n = sum(len(load_items(data_root, mode=m, policy=policy)) for m in MODES)
        counts.append(n)

    fig, ax = plt.subplots(figsize=(7.0, 3.0))
    ax_r    = ax.twinx()
    _render(ax, ax_r, POLICIES, series, counts)

    _save(fig, output_dir, "f3_modes_by_policy_all_storages")




def main():
    base_dir   = Path(__file__).resolve().parents[2]
    data_root  = base_dir / "data"
    output_dir = Path(__file__).resolve().parent / "outputs" / "figures"

    print("=" * 55)
    print("  ITEM-LEVEL BOXPLOT SUITE")
    print("=" * 55)

    # F1 — exemple sur FR_0446 / UnAuth / ALL
    print("\n  [F1] Pi/Ii/Ri by storage — UnAuth / FR_0446 / ALL")
    plot_f1_metrics_by_storage(
        data_root, output_dir,
        mode='UnAuth', policy='ALL'
    )

    # F2 — 4 figures, une par storage
    print("\n  [F2] Ri_Auth vs Ri_UnAuth by policy — per storage")
    plot_f2_modes_by_policy_per_storage(data_root, output_dir)

    # F3 — tous storages confondus
    print("\n  [F3] Ri_Auth vs Ri_UnAuth by policy — all storages")
    plot_f3_modes_by_policy_all_storages(data_root, output_dir)

    print("\n" + "=" * 55)
    print("  Done.")
    print("=" * 55)


if __name__ == "__main__":
    main()