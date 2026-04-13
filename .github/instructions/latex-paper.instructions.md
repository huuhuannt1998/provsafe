---
description: "Use when editing LaTeX paper files, updating numbers in tables, fixing references, or working on the ACM CCS submission. Covers paper conventions and number verification."
applyTo: "overleaf/**"
---
# LaTeX Paper Instructions

## Format
- ACM `acmart` sigconf format (anonymous submission)
- Sections in `overleaf/sections/01_intro.tex` through `11_conclusion.tex`
- Figures in `overleaf/figures/`

## Number Accuracy
- All numbers MUST match checkpoint data — verify with `python compute_paper_numbers.py`
- Use `python audit_paper.py` to compare paper numbers vs actual data
- 212 scenarios (172 attack + 40 benign), 9 attack categories
- Key numbers: ASR-IA 1.02% ± 0.34, TSR 95.00% ± 1.52, FPR 5.00%
- GPT-4o-mini: ASR 0.35%, TSR 99.50%
- Taint-Everything: ASR 0.00%, TSR 9.00%, FPR 91.00%

## Trial Counts
- Local models: 16,960 primary + 4,240 taint = 21,200
- GPT-4o-mini: 5,300
- Total: 26,500+

## Conventions
- Use `\textbf{}` for emphasis in tables, not `\emph{}`
- Wilson confidence intervals for all rates
- Fisher exact test for pairwise significance, Bonferroni correction for multiple comparisons
- InjecAgent tables may still need updating — check `results/injecagent/checkpoint.json`
