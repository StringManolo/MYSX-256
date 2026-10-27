#!/usr/bin/env bash

pandoc PAPER.md -o MYSX-paper.pdf --pdf-engine=xelatex -V mainfont="DejaVu Serif" -V monofont="DejaVu Sans Mono" -V mathfont="DejaVu Sans" -V geometry:margin=1in -V fontsize=11pt 2>&1
