"""
Generate evaluation results figure for PROVSAFE paper.
Creates bar chart comparing Attack Success Rate (ASR) across different defense systems.

Usage:
    python create_evaluation_figure.py

Output:
    figures/evaluation_results.pdf
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Data from evaluation results
systems = ['No\nDefense', 'Pattern\nFilter', 'Dual-LLM\nFilter', 'Policy\nOnly', 'PROVSAFE']
asr = [90.9, 18.2, 25.0, 25.4, 0.0]

# Color scheme: red (vulnerable) -> yellow (partial) -> green (secure)
colors = ['#d62728', '#ff7f0e', '#ffdd78', '#9ed8e5', '#2ca02c']

# Create figure
fig, ax = plt.subplots(figsize=(7, 5))

# Create bars
bars = ax.bar(systems, asr, color=colors, edgecolor='black', linewidth=1.5, width=0.6)

# Styling
ax.set_ylabel('Attack Success Rate (%)', fontsize=13, fontweight='bold')
ax.set_ylim(0, 100)
ax.set_yticks(np.arange(0, 101, 10))
ax.grid(axis='y', alpha=0.3, linestyle='--', linewidth=1)
ax.set_axisbelow(True)

# Add value labels on bars
for i, (s, a) in enumerate(zip(systems, asr)):
    ax.text(i, a + 2, f'{a}%', ha='center', va='bottom', 
            fontsize=11, fontweight='bold')

# Add perfect defense reference line
ax.axhline(0, color='green', linestyle='--', linewidth=2.5, alpha=0.6, zorder=1)
ax.text(4.3, 2, 'Perfect\nDefense', fontsize=9, color='green', 
        fontweight='bold', va='bottom', ha='right')

# Add 90.9 pp improvement annotation
ax.annotate('', xy=(0, asr[0]), xytext=(4, asr[4]),
            arrowprops=dict(arrowstyle='<->', lw=2.5, color='black', 
                          connectionstyle='arc3,rad=.3'))
ax.text(2, 65, '90.9 pp\nimprovement', fontsize=12, fontweight='bold',
        ha='center', va='center',
        bbox=dict(boxstyle='round,pad=0.6', facecolor='yellow', 
                 edgecolor='black', linewidth=1.5, alpha=0.8))

# Add provenance contribution annotation
ax.annotate('', xy=(3, asr[3]), xytext=(4, asr[4]),
            arrowprops=dict(arrowstyle='<->', lw=2, color='blue'))
ax.text(3.5, 12, '24.3 pp\nprovenance', fontsize=10, color='blue',
        fontweight='bold', ha='center',
        bbox=dict(boxstyle='round,pad=0.4', facecolor='white', 
                 edgecolor='blue', linewidth=1.5, alpha=0.9))

# Add statistical significance
ax.text(0.5, 0.98, 'p < 0.001, Cohen\'s d = 4.21', 
        transform=ax.transAxes, fontsize=10, va='top', ha='left',
        bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgray', 
                 edgecolor='black', linewidth=1, alpha=0.8))

# Add legend for pattern
policy_only_patch = mpatches.Patch(facecolor=colors[3], edgecolor='black', 
                                   linewidth=1.5, label='Ablation baseline')
legend = ax.legend(handles=[policy_only_patch], loc='upper right', 
                  fontsize=9, frameon=True, fancybox=True, shadow=True)

# Tight layout
plt.tight_layout()

# Save figure
output_path = 'figures/evaluation_results.pdf'
plt.savefig(output_path, dpi=300, bbox_inches='tight', format='pdf')
print(f'✓ Created: {output_path}')
print(f'  - Bar chart showing 90.9 pp ASR improvement')
print(f'  - Provenance contribution: 24.3 pp')
print(f'  - Statistical significance: p < 0.001, Cohen\'s d = 4.21')

# Also save as PNG for preview
output_path_png = 'figures/evaluation_results.png'
plt.savefig(output_path_png, dpi=300, bbox_inches='tight', format='png')
print(f'✓ Created preview: {output_path_png}')

plt.close()
