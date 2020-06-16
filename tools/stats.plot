# kAFL Status Plot
#
# Adopted from Redqueen kAFL-Fuzzer/common/evaluation.py
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann
# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#

# Launch as:
# $ gnuplot -c $tools/stats.plot $workdir/stats.csv

indata1=ARG1

set terminal wxt size 900,800 enhanced persist
set multiplot

set grid xtics linetype 0 linecolor rgb '#d0d0d0'
set grid ytics linetype 0 linecolor rgb '#d0d0d0'
set border linecolor rgb '#50c0f0'
set tics textcolor rgb '#000000'
set key outside
set size 1, 0.30
set datafile separator ';'

# auto-scale y axis but avoid empty [0:0] yrange warning when no values yet
set yrange [-0.1:*]

#set xlabel "Time"
set xdata time
set format x "%H:%M"
set timefmt "%s"
set style line 2
set style data line
set origin 0.0,0.66

## plot #1
plot indata1 using 1:2 title 'Execs/s' with line linecolor rgb '#0090ff' linewidth 2 smooth bezier, \
'' using 1:2 with filledcurve x1 title '' linecolor rgb '#0090ff' fillstyle transparent solid 0.2 noborder,

## plot #2
set origin 0.0,0.33
plot indata1 \
using 1:4 title 'Paths Pending' with lines linecolor rgb '#404040' linewidth 3, \
'' using 1:3 title 'Paths Total' with lines linecolor rgb '#C0C0C0' linewidth 2, \
'' using 1:11 title 'Favs Pending' with lines linecolor rgb '#808080' linewidth 3, \
'' using 1:5 title 'Favs Total' with lines linecolor rgb '#FF0000' linewidth 2, \
'' using 1:4 with filledcurve x1 title '' linecolor rgb '#808080' fillstyle transparent solid 0.5 noborder, \
'' using 1:3 with filledcurve x1 title '' linecolor rgb '#C0C0C0' fillstyle transparent solid 0.3 noborder, \
'' using 1:11 with filledcurve x1 title '' linecolor rgb '#404040' fillstyle transparent solid 0.5 noborder

## plot #3
set origin 0.0,0.0
plot indata1 using 1:6 title 'Unique Crashes' with lines linewidth 2, \
'' using 1:7 title 'Unique kASan' with lines linewidth 2, \
'' using 1:8 title 'Unique Timeout' with lines linewidth 2
## plot #4
#set origin 0.0,0.0
#plot indata1 using 0:15 title 'Blacklisted BB' with lines

unset multiplot
#pause 2
#reset
#reread
