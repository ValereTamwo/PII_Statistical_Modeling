
import json
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

matplotlib.rcParams.update({
    'font.family':        'serif',
    'font.size':          8,
    'axes.labelsize':     10,
    'axes.titlesize':     8,
    'axes.titleweight':   'normal',
    'xtick.labelsize':    9,
    'ytick.labelsize':    9,
    'legend.fontsize':    9,
    'legend.framealpha':  1.0,
    'legend.edgecolor':   '#aaaaaa',
    'legend.borderpad':   0.3,
    'axes.linewidth':     0.6,
    'xtick.major.width':  0.5,
    'ytick.major.width':  0.5,
    'xtick.major.size':   2.5,
    'ytick.major.size':   2.5,
    'xtick.direction':    'in',
    'ytick.direction':    'in',
    'axes.spines.top':    False,
    'grid.alpha':         0.30,
    'grid.linewidth':     0.4,
    'grid.color':         '#bbbbbb',
    'savefig.dpi':        300,
    'savefig.bbox':       'tight',
    'savefig.pad_inches': 0.04,
})

# ── CONSTANTES ──────────────────────────────────────────────
STORAGES       = ['cookie', 'localStorage', 'sessionStorage', 'IndexedDB']
STORAGE_LABELS = ['Cookie', 'localStorage', 'sessionStorage', 'IndexedDB']
MODES          = ['Auth', 'UnAuth']
ALPHA_KEYS     = ['id', 'ato', 'link', 'loc', 'prof', 'env']
ALPHA_GRID     = [round(x * 0.1, 1) for x in range(1, 11)]

DEFAULT_ALPHAS = {
    'id': 0.90, 'ato': 0.95, 'link': 0.85,
    'loc': 0.75, 'prof': 0.70, 'env': 0.50
}

# 6 couleurs + styles pour les dimensions
DIM_COLORS = {
    'id':   '#4472C4',
    'ato':  '#ED7D31',
    'link': '#C00000',
    'loc':  '#70AD47',
    'prof': '#7030A0',
    'env':  '#00B0F0',
}
DIM_MARKERS = {
    'id': 'o', 'ato': 's', 'link': 'D',
    'loc': '^', 'prof': 'v', 'env': 'P',
}
DIM_LINES = {
    'id': '-',  'ato': '--', 'link': '-',
    'loc': '-.','prof': '--','env':  ':',
}
DIM_LABELS = {
    'id':   r'$\alpha_{id}$',
    'ato':  r'$\alpha_{ato}$',
    'link': r'$\alpha_{link}$',
    'loc':  r'$\alpha_{loc}$',
    'prof': r'$\alpha_{prof}$',
    'env':  r'$\alpha_{env}$',
}

# Couleurs storages et modes
ST_COLORS  = {'cookie':'#C00000','localStorage':'#4472C4',
              'sessionStorage':'#70AD47','IndexedDB':'#ED7D31'}
MODE_COLORS = {'Auth':'#4472C4','UnAuth':'#C00000'}
MODE_LINES  = {'Auth':'-','UnAuth':'--'}
MODE_MARKERS= {'Auth':'o','UnAuth':'s'}


# ════════════════════════════════════════════════════════════
# UTILITAIRES
# ════════════════════════════════════════════════════════════

def _save(fig, out_dir: Path, stem: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / f'{stem}.pdf')
    fig.savefig(out_dir / f'{stem}.png')
    plt.close(fig)
    print(f'  Saved: {stem}.pdf / .png')


def _get_series(sens: dict, dim: str, field: str, sub: str) -> list:
    """Série de valeurs sur la grille alpha pour un champ donné."""
    return [sens['sensitivity_1d']['dimensions'][dim][str(v)][field][sub]
            for v in ALPHA_GRID]


def _shared_dim_legend(fig, ncol=6, y=-0.06):
    """Generates a synchronized legend for all 6 model dimensions."""
    handles = [
        plt.Line2D([0],[0],
                   color=DIM_COLORS[d], lw=1.3,
                   ls=DIM_LINES[d],
                   marker=DIM_MARKERS[d], markersize=4,
                   markerfacecolor='white',
                   markeredgecolor=DIM_COLORS[d],
                   markeredgewidth=0.8,
                   label=DIM_LABELS[d])
        for d in ALPHA_KEYS
    ]
    fig.legend(handles=handles,
               loc='lower center', bbox_to_anchor=(0.5, y),
               ncol=ncol, handlelength=1.4, handleheight=0.8,
               columnspacing=1.0, borderpad=0.3,
               fontsize=7, frameon=True)


def _plot_6dim_curves(ax, sens, field, sub_key, ref_val,
                      highlight_dims=None):
    """
    Renders 6 sensitivity curves on the provided axis.
    highlight_dims: dimensions with higher visual salience (active drivers).
    """
    if highlight_dims is None:
        highlight_dims = ['link', 'prof']

    for dim in ALPHA_KEYS:
        ys  = _get_series(sens, dim, field, sub_key)
        lw  = 1.2 if dim in highlight_dims else 0.6
        alp = 1.0 if dim in highlight_dims else 0.35
        ax.plot(ALPHA_GRID, ys,
                color=DIM_COLORS[dim],
                lw=lw, ls=DIM_LINES[dim],
                alpha=alp,
                marker=DIM_MARKERS[dim],
                markersize=3.5 if dim in highlight_dims else 2.5,
                markerfacecolor='white',
                markeredgecolor=DIM_COLORS[dim],
                markeredgewidth=0.7,
                label=DIM_LABELS[dim])
        # Marqueur valeur par défaut
        dv = DEFAULT_ALPHAS[dim]
        dv_key = str(round(dv, 1))
        if dv_key in sens['sensitivity_1d']['dimensions'][dim]:
            dy = sens['sensitivity_1d']['dimensions'][dim][dv_key][field][sub_key]
            ax.scatter([dv], [dy],
                       color=DIM_COLORS[dim], s=18, zorder=6,
                       marker='D', alpha=alp)

    # Reference baseline
    ax.axhline(ref_val, color='#999999', lw=0.6,
               ls='--', zorder=0, alpha=0.7)


# ════════════════════════════════════════════════════════════
# FIG A0 — Bar chart Delta par dimension
# ════════════════════════════════════════════════════════════

def plot_fig_a0_delta_summary(sens: dict, out_dir: Path):
    """
    Bar chart : Delta_k = mean_Ri(alpha=1.0) - mean_Ri(alpha=0.1)
    pour chaque dimension. Ligne seuil à 0.05.
    """
    dims_data = sens['sensitivity_1d']['dimensions']
    deltas = {}
    for dim in ALPHA_KEYS:
        ys = [dims_data[dim][str(v)]['global_mean_ri'] for v in ALPHA_GRID]
        # deltas[dim] = round(max(ys) - min(ys), 4)
        deltas[dim] = round(dims_data[dim]['1.0']['global_mean_ri'] - dims_data[dim]['0.1']['global_mean_ri'], 4)

    fig, ax = plt.subplots(figsize=(5.0, 2.8))
    xs     = np.arange(len(ALPHA_KEYS))
    colors = [DIM_COLORS[d] for d in ALPHA_KEYS]
    ax.bar(xs, [deltas[d] for d in ALPHA_KEYS],
           color=colors, edgecolor='black', linewidth=0.4, width=0.6)

    ax.axhline(0.05, color='#888888', lw=0.8, ls='--', zorder=0)
    ax.text(len(ALPHA_KEYS) - 0.05, 0.053, 'threshold',
            ha='right', fontsize=6, color='#888888')

    ax.set_xticks(xs)
    ax.set_xticklabels([DIM_LABELS[d] for d in ALPHA_KEYS])
    ax.set_ylabel(r'$\Delta\,\overline{R}_i$  (max $-$ min)')
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)

    for xi, dim in zip(xs, ALPHA_KEYS):
        ax.text(xi, deltas[dim] + 0.003, f'{deltas[dim]:.3f}',
                ha='center', va='bottom', fontsize=6.5)

    _save(fig, out_dir, 'appendix_A0_delta_summary')


# ════════════════════════════════════════════════════════════
# FIG A1 — 4 subplots par STORAGE, 6 courbes dim
# ════════════════════════════════════════════════════════════

def plot_fig_a1_by_storage(sens: dict, out_dir: Path):
    """
    4 figures séparées — une par storage (publication-ready).
    """

    ref_storage = sens['sensitivity_1d']['reference']['aggregated']['mean_by_storage']

    for st, st_label in zip(STORAGES, STORAGE_LABELS):

        fig, ax = plt.subplots(figsize=(3.4, 2.6))  # format colonne papier

        # Courbes
        _plot_6dim_curves(
            ax, sens,
            field='mean_by_storage',
            sub_key=st,
            ref_val=ref_storage[st]
        )

        # ax.set_title(st_label, pad=2.5,
        #              color=ST_COLORS[st],
        #              fontweight='normal')

        ax.set_xlabel(r'$\alpha_k$')
        ax.set_ylabel(r'$\overline{R}_i$')

        ax.set_xticks(ALPHA_GRID)
        ax.set_xlim(0.05, 1.05)

        ax.yaxis.grid(True)
        ax.set_axisbelow(True)

        # ── SPINES clean (comme boxplots)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        # ── Annotations Δ (plus propres)
        y_pos = 0.05
        for dim in ['link', 'prof']:
            ys = _get_series(sens, dim, 'mean_by_storage', st)
            delta = max(ys) - min(ys)

            ax.text(0.98, y_pos,
                    f'{DIM_LABELS[dim]} Δ={delta:.3f}',
                    transform=ax.transAxes,
                    ha='right', va='bottom',
                    fontsize=9,
                    color=DIM_COLORS[dim])
            y_pos += 0.10

        # ── Légende compacte (locale)
        handles = [
            plt.Line2D([0],[0],
                       color=DIM_COLORS[d],
                       lw=1.2 if d in ['link','prof'] else 0.8,
                       ls=DIM_LINES[d],
                       marker=DIM_MARKERS[d],
                       markersize=3,
                       markerfacecolor='white',
                       markeredgewidth=0.7,
                       label=DIM_LABELS[d])
            for d in ALPHA_KEYS
        ]

        ax.legend(handles=handles,
                  loc='upper left',
                  ncol=2,
                  frameon=True,
                  handlelength=1.2,
                  columnspacing=0.6,
                  borderpad=0.3)

        # ── SAVE
        stem = f'appendix_A1_{st}'
        _save(fig, out_dir, stem)


# ════════════════════════════════════════════════════════════
# FIG A2 — 2 subplots par MODE, 6 courbes dim
# ════════════════════════════════════════════════════════════

# def plot_fig_a2_by_mode(sens: dict, out_dir: Path):
#     """
   
#     """
#     ref_mode = sens['sensitivity_1d']['reference']['aggregated'] \
#                    ['mean_by_mode']

#     fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.0),
#                               gridspec_kw={'wspace': 0.30})

#     for ax, mode in zip(axes, MODES):
#         _plot_6dim_curves(ax, sens,
#                           field='mean_by_mode',
#                           sub_key=mode,
#                           ref_val=ref_mode[mode])

#         # ax.set_title(f'Session mode: {mode}',
#         #              pad=3, color=MODE_COLORS[mode],
#         #              fontweight='bold')
#         ax.set_xlabel(r'$\alpha_k$ ')
#         ax.set_ylabel(r'Mean $\overline{R}_i$')
#         ax.set_xticks(ALPHA_GRID)
#         ax.set_xticklabels([str(v) for v in ALPHA_GRID])
#         ax.set_xlim(0.05, 1.05)
#         ax.yaxis.grid(True)
#         ax.set_axisbelow(True)

#         # Annotation Δ pour link et prof
#         for i, dim in enumerate(['link', 'prof']):
#             ys = _get_series(sens, dim, 'mean_by_mode', mode)
#             delta = max(ys) - min(ys)
#             ax.text(0.98, 0.05 + i * 0.10,
#                     f'{DIM_LABELS[dim]} $\\Delta={delta:.3f}$',
#                     transform=ax.transAxes,
#                     ha='right', va='bottom', fontsize=5.5,
#                     color=DIM_COLORS[dim])

#     # # Note mode-invariance
#     # fig.text(0.5, -0.01,
#     #          r'$\alpha_k$ sensitivity is invariant to session mode.',
#     #          ha='center', fontsize=6.5, style='italic', color='#555555')

#     _shared_dim_legend(fig, ncol=6, y=-0.14)
#     _save(fig, out_dir, 'appendix_A2_by_mode')
def plot_fig_a2_by_mode(sens: dict, out_dir: Path):
    """
    """

    ref_mode = sens['sensitivity_1d']['reference']['aggregated']['mean_by_mode']

    for mode in MODES:

        fig, ax = plt.subplots(figsize=(3.4, 2.6))  # format colonne

        _plot_6dim_curves(
            ax, sens,
            field='mean_by_mode',
            sub_key=mode,
            ref_val=ref_mode[mode]
        )

        # ── AXES (clean, sans titre)
        ax.set_xlabel(r'$\alpha_k$')
        ax.set_ylabel(r'$\overline{R}_i$')

        ax.set_xticks(ALPHA_GRID)
        ax.set_xlim(0.05, 1.05)

        ax.yaxis.grid(True)
        ax.set_axisbelow(True)

        # ── SPINES clean (comme A1 / boxplots)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        y_pos = 0.05
        for dim in ['link', 'prof']:
            ys = _get_series(sens, dim, 'mean_by_mode', mode)
            delta = max(ys) - min(ys)

            ax.text(0.98, y_pos,
                    f'{DIM_LABELS[dim]} Δ={delta:.3f}',
                    transform=ax.transAxes,
                    ha='right', va='bottom',
                    fontsize=9,
                    color=DIM_COLORS[dim])
            y_pos += 0.10

        # ── Légende locale compacte
        handles = [
            plt.Line2D([0],[0],
                       color=DIM_COLORS[d],
                       lw=1.2 if d in ['link','prof'] else 0.6,
                       ls=DIM_LINES[d],
                       marker=DIM_MARKERS[d],
                       markersize=3,
                       markerfacecolor='white',
                       markeredgewidth=0.7,
                       label=DIM_LABELS[d])
            for d in ALPHA_KEYS
        ]

        ax.legend(handles=handles,
                  loc='upper left',
                  ncol=2,
                  frameon=True,
                  handlelength=1.2,
                  columnspacing=0.6,
                  borderpad=0.3,
                  fontsize=6)

        # ── SAVE
        stem = f'appendix_A2_{mode}'
        _save(fig, out_dir, stem)

# ════════════════════════════════════════════════════════════
# TAB A1 — Heatmap ranking stability
# ════════════════════════════════════════════════════════════

def plot_tab_a1_ranking_stability(sens: dict, out_dir: Path):
    rankings_def = {
        'UnAuth $>$ Auth': 'unauth_gt_auth',
        'ALL $>$ NONE':    'all_gt_none',
        'IDB $>$ Cookie':  'idb_gt_cookie',
    }

    details = []
    for dim in ALPHA_KEYS:
        for val in ALPHA_GRID:
            d  = sens['sensitivity_1d']['dimensions'][dim][str(val)]
            r1 = d['by_mode'].get('UnAuth',0)    >= d['by_mode'].get('Auth',0)
            r2 = d['by_policy'].get('ALL',0)      >= d['by_policy'].get('NONE',0)
            r3 = d['by_storage'].get('IndexedDB',0) >= d['by_storage'].get('cookie',0)
            details.append({'dim':dim,'alpha':val,
                             'unauth_gt_auth':r1,
                             'all_gt_none':r2,
                             'idb_gt_cookie':r3})

    # CSV
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir/'appendix_ranking_stability.csv','w') as f:
        f.write('dimension,alpha,UnAuth>Auth,ALL>NONE,IDB>Cookie\n')
        for r in details:
            f.write(f"{r['dim']},{r['alpha']},"
                    f"{r['unauth_gt_auth']},{r['all_gt_none']},"
                    f"{r['idb_gt_cookie']}\n")

    n = len(details)
    print(f'\n  RANKING STABILITY — {n} configurations')
    print(f'  {"Ranking":<22} {"Y":>5}  {"N":>5}  {"rate":>6}')
    print('  '+'-'*40)
    for name, key in rankings_def.items():
        ok = sum(r[key] for r in details)
        print(f'  {name:<22} {ok:>5}  {n-ok:>5}  {ok/n*100:>5.1f}%')

    # Heatmap 3 × (6×10)
    fig, axes = plt.subplots(1, 3, figsize=(7.0, 2.8),
                              gridspec_kw={'wspace': 0.45})

    for ax, (name, key) in zip(axes, rankings_def.items()):
        matrix = np.zeros((len(ALPHA_KEYS), len(ALPHA_GRID)))
        for i, dim in enumerate(ALPHA_KEYS):
            for j in range(len(ALPHA_GRID)):
                matrix[i,j] = 1.0 if details[i*len(ALPHA_GRID)+j][key] else 0.0

        ax.imshow(matrix, cmap='RdYlGn', vmin=0, vmax=1, aspect='auto')

        for i in range(len(ALPHA_KEYS)):
            for j in range(len(ALPHA_GRID)):
                ax.text(j, i, 'Y' if matrix[i,j] else 'N',
                        ha='center', va='center', fontsize=6,
                        color='#0d3d0d' if matrix[i,j] else 'white',
                        fontweight='bold' if matrix[i,j] else 'normal')

        ax.set_xticks(range(len(ALPHA_GRID)))
        ax.set_xticklabels([str(v) for v in ALPHA_GRID], fontsize=5.5)
        ax.set_yticks(range(len(ALPHA_KEYS)))
        ax.set_yticklabels([DIM_LABELS[d] for d in ALPHA_KEYS], fontsize=6)
        ax.set_xlabel(r'$\alpha_k$', fontsize=7)
        total = int(matrix.sum())
        ax.set_title(f'{name}\n({total}/{n})', fontsize=6.5, pad=3)

    fig.suptitle('Ranking stability across all 60 sensitivity configurations',
                 fontsize=7.5, y=1.04)
    _save(fig, out_dir, 'appendix_A1_ranking_heatmap')



def main():
    base_dir  = Path(__file__).resolve().parents[2]
    sens_path = base_dir / 'data' / 'reports' / 'sensitivity_full_pipeline.json'
    out_dir   = Path(__file__).resolve().parent / 'outputs' / 'figures' / 'appendix'

    if not sens_path.exists():
        print(f'  ERROR: {sens_path} not found.')
        return

    print('='*60)
    print('  APPENDIX SENSITIVITY FIGURES')
    print('='*60)

    with open(sens_path, encoding='utf-8') as f:
        sens = json.load(f)

    print('\n  [A0] Delta summary bar chart...')
    plot_fig_a0_delta_summary(sens, out_dir)

    print('\n  [A1] Curves by storage (4 subplots × 6 dims)...')
    plot_fig_a1_by_storage(sens, out_dir)

    print('\n  [A2] Curves by mode (2 subplots × 6 dims)...')
    plot_fig_a2_by_mode(sens, out_dir)

    print('\n  [Tab A1] Ranking stability heatmap...')
    plot_tab_a1_ranking_stability(sens, out_dir)

    print(f'\n  Done. Output: {out_dir}')


if __name__ == '__main__':
    main()




def plot_step2_distributions(sens: dict, out_dir: Path):
    """
    Figure : heatmap mean_Ri par storage × scénario (MIN/DEFAULT/MAX).
    + tableau IQR en annotation.
    """
    import matplotlib.pyplot as plt
    import numpy as np

    scenarios = ['alphas_min', 'alphas_default', 'alphas_max']
    sc_labels = ['MIN\n(all α=0.1)', 'DEFAULT\n(calibrated)', 'MAX\n(all α=1.0)']
    sr = sens.get('sensitivity_range', {})
    if not sr:
        print('  [Step2] sensitivity_range not found in JSON — skipping')
        return

    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.0),
                              gridspec_kw={'wspace': 0.45})

    # Subplot 1 : mean_Ri par storage × scénario
    ax = axes[0]
    matrix = np.zeros((len(STORAGES), len(scenarios)))
    for j, sc in enumerate(scenarios):
        for i, st in enumerate(STORAGES):
            val = sr.get(sc, {}).get('mean_by_storage', {}).get(st, 0.)
            matrix[i, j] = val

    im = ax.imshow(matrix, cmap='YlOrRd', vmin=0.0, vmax=1.0, aspect='auto')
    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label=r'Mean $\overline{R}_i$')
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels(sc_labels, fontsize=6.5)
    ax.set_yticks(range(len(STORAGES)))
    ax.set_yticklabels(STORAGE_LABELS, fontsize=7)
    ax.set_title(r'Mean $\overline{R}_i$ by storage $\times$ scenario', fontsize=7.5, pad=4)
    for i in range(len(STORAGES)):
        for j in range(len(scenarios)):
            ax.text(j, i, f'{matrix[i,j]:.3f}',
                    ha='center', va='center', fontsize=6.5,
                    color='white' if matrix[i,j] > 0.65 else 'black')

    # Subplot 2 : IQR item-level par storage × scénario
    ax2 = axes[1]
    iqr_matrix = np.zeros((len(STORAGES), len(scenarios)))
    for j, sc in enumerate(scenarios):
        dist = sr.get(sc, {}).get('dist_by_storage', {})
        for i, st in enumerate(STORAGES):
            iqr_matrix[i, j] = dist.get(st, {}).get('iqr') or 0.

    im2 = ax2.imshow(iqr_matrix, cmap='Blues', vmin=0.0, vmax=0.5, aspect='auto')
    plt.colorbar(im2, ax=ax2, fraction=0.046, pad=0.04, label='IQR')
    ax2.set_xticks(range(len(scenarios)))
    ax2.set_xticklabels(sc_labels, fontsize=6.5)
    ax2.set_yticks(range(len(STORAGES)))
    ax2.set_yticklabels(STORAGE_LABELS, fontsize=7)
    ax2.set_title('IQR item-level by storage $\\times$ scenario', fontsize=7.5, pad=4)
    for i in range(len(STORAGES)):
        for j in range(len(scenarios)):
            ax2.text(j, i, f'{iqr_matrix[i,j]:.3f}',
                     ha='center', va='center', fontsize=6.5,
                     color='white' if iqr_matrix[i,j] > 0.35 else 'black')

    _save(fig, out_dir, 'appendix_step2_distributions')



def plot_step4_drivers(sens: dict, out_dir: Path):
    """
    Heatmap Δ = mean_Ri(max) - mean_Ri(min) par storage × dimension.
    Met en évidence le driver principal de chaque storage.
    """
    import matplotlib.pyplot as plt
    import numpy as np

    drivers = sens.get('drivers_by_storage')
    if not drivers:
        # Calculer depuis sensitivity_1d
        dims_data = sens['sensitivity_1d']['dimensions']
        drivers = {}
        for st in STORAGES:
            drivers[st] = {}
            for dim in ALPHA_KEYS:
                ys = [dims_data[dim][str(v)]['mean_by_storage'][st]
                      for v in ALPHA_GRID]
                drivers[st][dim] = {'delta': round(max(ys)-min(ys), 4)}
            main = max(ALPHA_KEYS, key=lambda d: drivers[st][d]['delta'])
            drivers[st]['_main_driver'] = main

    fig, ax = plt.subplots(figsize=(5.5, 3.0))

    matrix = np.zeros((len(STORAGES), len(ALPHA_KEYS)))
    for i, st in enumerate(STORAGES):
        for j, dim in enumerate(ALPHA_KEYS):
            matrix[i, j] = drivers[st].get(dim, {}).get('delta', 0.)

    im = ax.imshow(matrix, cmap='Reds', vmin=0., vmax=matrix.max(), aspect='auto')
    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04,
                 label=r'$\Delta\,\overline{R}_i$ (max$-$min)')

    ax.set_xticks(range(len(ALPHA_KEYS)))
    ax.set_xticklabels([DIM_LABELS[d] for d in ALPHA_KEYS], fontsize=7)
    ax.set_yticks(range(len(STORAGES)))
    ax.set_yticklabels(STORAGE_LABELS, fontsize=7)
    ax.set_title(r'Risk driver intensity $\Delta$ per storage $\times$ dimension',
                 fontsize=7.5, pad=4)

    for i, st in enumerate(STORAGES):
        main = drivers[st].get('_main_driver')
        for j, dim in enumerate(ALPHA_KEYS):
            val = matrix[i, j]
            weight = 'bold' if dim == main else 'normal'
            border = '[ ' if dim == main else ''
            border_r= ' ]' if dim == main else ''
            ax.text(j, i, f'{border}{val:.3f}{border_r}',
                    ha='center', va='center', fontsize=6,
                    fontweight=weight,
                    color='white' if val > 0.2 else 'black')

    _save(fig, out_dir, 'appendix_step4_drivers')