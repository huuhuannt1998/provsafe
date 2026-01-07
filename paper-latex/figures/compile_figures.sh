#!/bin/bash
# Script to compile TikZ figures to PDF

set -e

FIGURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$FIGURES_DIR"

echo "Compiling TikZ figures to PDF..."
echo "================================"

# Check if pdflatex is available
if ! command -v pdflatex &> /dev/null; then
    echo "ERROR: pdflatex not found!"
    echo ""
    echo "Please install LaTeX:"
    echo "  macOS:   brew install --cask mactex-no-gui"
    echo "           or download from: https://www.tug.org/mactex/"
    echo "  Linux:   sudo apt-get install texlive-full"
    echo "  Windows: Download MiKTeX from https://miktex.org/"
    echo ""
    echo "Alternatively, compile online:"
    echo "  1. Go to https://www.overleaf.com/"
    echo "  2. Upload .tex files"
    echo "  3. Download compiled PDFs"
    exit 1
fi

# Compile each figure
for tex_file in attack_example.tex architecture.tex provenance_graph.tex; do
    if [ -f "$tex_file" ]; then
        echo "Compiling $tex_file..."
        pdflatex -interaction=nonstopmode "$tex_file" > /dev/null 2>&1
        
        # Check if PDF was created
        pdf_file="${tex_file%.tex}.pdf"
        if [ -f "$pdf_file" ]; then
            echo "  ✓ Created: $pdf_file"
        else
            echo "  ✗ Failed to create: $pdf_file"
        fi
    else
        echo "  ! Not found: $tex_file"
    fi
done

# Clean up auxiliary files
echo ""
echo "Cleaning up auxiliary files..."
rm -f *.aux *.log *.out *.nav *.snm *.toc

echo ""
echo "================================"
echo "Compilation complete!"
echo ""
echo "Generated PDFs:"
ls -lh *.pdf 2>/dev/null || echo "  (No PDFs generated)"
echo ""
echo "You can now include these figures in your paper:"
echo '  \includegraphics[width=\columnwidth]{figures/attack_example.pdf}'
echo '  \includegraphics[width=\columnwidth]{figures/architecture.pdf}'
echo '  \includegraphics[width=\columnwidth]{figures/provenance_graph.pdf}'
