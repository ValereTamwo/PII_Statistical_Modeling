import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

plt.style.use('seaborn-v0_8-whitegrid')
sns.set_context("paper", font_scale=1.8)
COLORS = {"Volume": "#3498db", "Intensity": "#e74c3c"}

AXIS_KW = dict(fontsize=18, fontweight='bold')


class RiskVisualizer:
    def __init__(self, json_path, output_dir):
        with open(json_path, 'r') as f:
            self.data = json.load(f)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def plot_storage_contrast(self):
        """Volume vs Intensity par Storage API."""
        storage_names = list(self.data['by_storage'].keys())
        df = pd.DataFrame({
            'Storage': storage_names * 2,
            'Score': [self.data['by_storage'][s] for s in storage_names] +
                     [self.data['by_storage_mean'][s] for s in storage_names],
            'Metric': ['Cumulative Risk (Volume)'] * len(storage_names) +
                      ['Risk Intensity (Mean)'] * len(storage_names)
        })
        plt.figure(figsize=(12, 7))
        ax = sns.barplot(x='Storage', y='Score', hue='Metric', data=df,
                         palette=[COLORS['Volume'], COLORS['Intensity']])
        plt.title("Technical Exposure: Volume vs. Intensity per Storage API", pad=20, fontsize=18, fontweight='bold')
        ax.set_xlabel("Storage API", **AXIS_KW)
        ax.set_ylabel("Normalized Risk Score [0, 1]", **AXIS_KW)
        plt.ylim(0, 1.1)
        plt.legend(loc='upper left', fontsize=16)
        plt.annotate('Highest Intensity\nbut Low Volume',
                     xy=(1, 0.61), xytext=(1.6, 0.82),
                     arrowprops=dict(facecolor='black', shrink=0.05),
                     fontsize=16, color='red')
        ax.tick_params(axis='both', labelsize=16)
        plt.tight_layout()
        plt.savefig(self.output_dir / "storage_contrast.pdf", dpi=300)
        plt.close()
        print("  Plot saved: storage_contrast.pdf")

    def plot_policy_paradox(self):
        """Consent paradox : volume chute, intensité plate."""
        policies = ["ALL", "PARTIAL", "NONE"]
        df = pd.DataFrame({
            'Policy': policies * 2,
            'Score': [self.data['by_policy'][p] for p in policies] +
                     [self.data['by_policy_mean'][p] for p in policies],
            'Metric': ['Cumulative Risk (Volume)'] * 3 + ['Risk Intensity (Mean)'] * 3
        })
        plt.figure(figsize=(10, 6))
        ax = sns.lineplot(x='Policy', y='Score', hue='Metric', data=df, marker='o',
                          palette=[COLORS['Volume'], COLORS['Intensity']],
                          linewidth=3, markersize=10)
        plt.title("The Consent Paradox: Opt-out reduces volume, not intensity", pad=20, fontsize=17, fontweight='bold')
        ax.set_xlabel("Consent Policy", **AXIS_KW)
        ax.set_ylabel("Normalized Risk Score", **AXIS_KW)
        plt.ylim(0, 1.1)
        ax.tick_params(axis='both', labelsize=13)
        plt.legend(fontsize=16)
        plt.tight_layout()
        plt.savefig(self.output_dir / "policy_paradox.pdf", dpi=300)
        plt.close()
        print("  Plot saved: policy_paradox.pdf")

    def plot_mode_heatmap(self):
        """Heatmap intensité seule — vmin=0, vmax=1."""
        modes    = ["Auth", "UnAuth"]
        policies = ["ALL", "PARTIAL", "NONE"]
        matrix   = [[self.data['by_mode_policy_mean'][m][p]
                      for p in policies] for m in modes]
        plt.figure(figsize=(12, 8))
        ax = sns.heatmap(matrix, annot=True, fmt=".3f",
                         xticklabels=policies, yticklabels=modes,
                         cmap="YlOrRd", vmin=0.0, vmax=1.0,
                         annot_kws={"size": 14},
                         cbar_kws={'label': 'Risk Intensity'})
        plt.title("Risk Intensity Heatmap (Mode vs. Policy)", fontsize=17, fontweight='bold')
        ax.set_xlabel("Consent Policy", **AXIS_KW)
        ax.set_ylabel("Session Mode", **AXIS_KW)
        ax.tick_params(axis='both', labelsize=13)
        ax.collections[0].colorbar.ax.tick_params(labelsize=12)
        ax.collections[0].colorbar.set_label('Risk Intensity', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(self.output_dir / "risk_heatmap.png", dpi=300)
        plt.close()
        print("  Plot saved: risk_heatmap.png")

    def plot_dual_heatmap(self):
        """Heatmap double annotation : couleur = volume, texte = Vol + Int."""
        modes    = ["Auth", "UnAuth"]
        policies = ["ALL", "PARTIAL", "NONE"]
        intensity = np.array([[self.data['by_mode_policy_mean'][m][p]
                                for p in policies] for m in modes])
        volume    = np.array([[self.data['by_mode_policy'][m][p]
                                for p in policies] for m in modes])
        fig, ax = plt.subplots(figsize=(11, 5))
        sns.heatmap(volume, ax=ax,
                    xticklabels=policies, yticklabels=modes,
                    cmap="YlOrRd", vmin=0.0, vmax=1.0,
                    annot=False, linewidths=0.5,
                    cbar_kws={'label': 'Cumulative Risk (Volume)'})
        for i in range(len(modes)):
            for j in range(len(policies)):
                col = 'white' if volume[i, j] > 0.55 else '#333333'
                ax.text(j + 0.5, i + 0.35, f"Vol: {volume[i, j]:.2f}",
                        ha='center', va='center',
                        fontsize=14, fontweight='bold', color=col)
                ax.text(j + 0.5, i + 0.65, f"Int: {intensity[i, j]:.3f}",
                        ha='center', va='center',
                        fontsize=12, fontweight='bold', color=col)
        ax.set_title("Risk Volume & Intensity — Mode × Policy\n"
                     "(Color = cumulative volume  |  Int = mean per-item intensity)",
                     pad=16, fontsize=14, fontweight='bold')
        ax.set_xlabel("Consent Policy", **AXIS_KW)
        ax.set_ylabel("Session Mode", **AXIS_KW)
        ax.tick_params(axis='both', labelsize=13)
        ax.collections[0].colorbar.ax.tick_params(labelsize=12)
        ax.collections[0].colorbar.set_label('Cumulative Risk (Volume)', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(self.output_dir / "dual_heatmap.pdf", dpi=300)
        plt.close()
        print("  Plot saved: dual_heatmap.pdf")


def main():
    base_dir   = Path(__file__).resolve().parents[2]
    json_path  = base_dir / "data" / "reports" / "aggregated_risk_data.json"
    output_dir = Path(__file__).resolve().parent / "outputs" / "visualizations"

    viz = RiskVisualizer(json_path, output_dir)

    print("=" * 65)
    print("  RISK VISUALIZER")
    print("=" * 65)
    viz.plot_storage_contrast()
    viz.plot_policy_paradox()
    viz.plot_mode_heatmap()
    viz.plot_dual_heatmap()
    print("=" * 65)
    print(f"  All plots generated in: {output_dir}")
    print("=" * 65)


if __name__ == "__main__":
    main()