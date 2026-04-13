---
description: "Verify all numbers in the paper match actual experimental data"
agent: "paper-updater"
---
Audit the PROVSAFE paper numbers against checkpoint data:

1. Run `python compute_paper_numbers.py` to compute verified numbers
2. Run `python audit_paper.py` to compare paper vs data
3. If any mismatches are found, list them with the correct values
4. Ask before making any edits to fix mismatches
