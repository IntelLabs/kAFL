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


# align plots
set lmargin 10
set rmargin 25

# auto-scale y axis but avoid empty [0:0] yrange warning when no values yet
set yrange  [-0.1:*]
set ytics nomirror
set y2range [-0.1:*]
set y2tics


# plot over test cases or elapsed time?
set xlabel "Cases"
# set xlabel "Time"
# set xdata time
# set format x "%H:%M"
# set timefmt "%s"

# logscale?
#set logscale x
#set xrange  [1:*]

set style line 2
set style data line

## plot #1
#set ylabel "Execs"
set y2label "Favs"
set origin 0.0,0.66
plot indata1 using 12:2 title 'Execs/s' with line linecolor rgb '#0090ff' linewidth 2 smooth bezier, \
'' using 12:2 with filledcurve x1 title '' linecolor rgb '#0090ff' fillstyle transparent solid 0.2 noborder, \
'' using 12:11 title 'Favs WIP' with lines linecolor rgb '#808080' linewidth 3 axes x1y2, \
'' using 12:5 title 'Favs Total' with lines linecolor rgb '#FF0000' linewidth 2 axes x1y2
#'' using 12:10 title 'Cycles' with lines linecolor rgb '#C0C0C0' linewidth 2 axes x1y2


## plot #2
unset y2tics
unset y2label
set origin 0.0,0.33
plot indata1 \
using 12:13 title 'Edges' with lines linecolor rgb '#404040' linewidth 3

## plot #3
set origin 0.0,0.0
plot indata1 using 12:6 title 'Crashes' with lines linewidth 2, \
'' using 12:7 title 'kASan' with lines linewidth 2, \
'' using 12:8 title 'Timeout' with lines linewidth 2
## plot #4
#set origin 0.0,0.0
#plot indata1 using 0:15 title 'Blacklisted BB' with lines

unset multiplot
#pause 2
#reset
#reread
