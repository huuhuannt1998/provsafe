# TikZ Figures for PROVSAFE Paper

## ✅ Created TikZ Diagrams

All three critical figures have been created as professional TikZ diagrams:

1. **attack_example.tex** - Indirect prompt injection attack flow (Figure 1)
2. **architecture.tex** - System architecture with all components (Figure 2)  
3. **provenance_graph.tex** - Provenance DAG with trust propagation (Figure 3)
4. **evaluation_results.pdf** - Bar chart (already compiled) (Figure 4) ✓

## 📋 How to Compile to PDF

### Option 1: Install LaTeX Locally (Recommended)

#### macOS:
```bash
# Install MacTeX (3.9 GB, includes all packages)
brew install --cask mactex-no-gui

# Or download installer from:
# https://www.tug.org/mactex/mactex-download.html
```

#### Linux:
```bash
sudo apt-get install texlive-full texlive-pictures
```

#### After Installation:
```bash
cd /Users/huanbui/Desktop/provsafe/paper-latex/figures
./compile_figures.sh
```

This will generate:
- `attack_example.pdf`
- `architecture.pdf`
- `provenance_graph.pdf`

### Option 2: Use Overleaf (Online, No Installation)

1. Go to https://www.overleaf.com/ (free account)
2. Create a new project
3. Upload each `.tex` file
4. Overleaf will auto-compile
5. Download the resulting PDFs
6. Move them to the `figures/` directory

### Option 3: Manual Compilation

If you have LaTeX installed:
```bash
cd /Users/huanbui/Desktop/provsafe/paper-latex/figures
pdflatex attack_example.tex
pdflatex architecture.tex
pdflatex provenance_graph.tex
```

## 🎨 Figure Descriptions

### Figure 1: Attack Example (attack_example.pdf)
- **Purpose**: Motivate the problem in the introduction
- **Content**: 6-step attack flow with color-coded nodes
- **Style**: Vertical flow diagram showing attack → processing → defense

### Figure 2: Architecture (architecture.pdf)
- **Purpose**: Show system components in overview/design
- **Content**: Layered architecture with security perimeter highlighted
- **Style**: Component diagram with numbered data flows (1-10)

### Figure 3: Provenance Graph (provenance_graph.pdf)
- **Purpose**: Illustrate provenance tracking in design
- **Content**: DAG with 7 nodes showing trust propagation
- **Style**: Different shapes for node types (rectangle, diamond, ellipse)

### Figure 4: Evaluation Results (evaluation_results.pdf) ✓
- Already compiled and ready
- Bar chart comparing ASR across 5 systems

## 📝 Using Figures in Paper

Once compiled, reference them in your LaTeX:

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{figures/attack_example.pdf}
  \caption{Indirect prompt injection attack...}
  \label{fig:attack-example}
\end{figure}
```

## 📊 Status

- [x] Figure 1: attack_example.tex (TikZ created)
- [x] Figure 2: architecture.tex (TikZ created)
- [x] Figure 3: provenance_graph.tex (TikZ created)
- [x] Figure 4: evaluation_results.pdf (Compiled) ✓
- [ ] Compile TikZ to PDF (requires LaTeX)

**Next**: Install LaTeX and run `./compile_figures.sh`!
