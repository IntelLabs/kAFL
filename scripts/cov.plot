#
# Plot coverage over time based on full trace outputs.
#
# Usage:
# $ gnuplot -c $tools/cov.plot $workdir/traces/coverage.csv
#

indata1=ARG1

#set terminal png size 900,800 enhanced
#set output cov.png

set terminal wxt size 900,800 enhanced persist


set xlabel "Time"
set ylabel "#BBs"
set autoscale

set grid xtics linetype 0 linecolor rgb '#e0e0e0'
set grid ytics linetype 0 linecolor rgb '#e0e0e0'
set border linecolor rgb '#50c0f0'
set tics textcolor rgb '#000000'
#set key outside

#set xdata time
#set timefmt "%S"
#set xtics time format "%H:%M"
set xtics time format "Day %d\n%H:%M"

set datafile separator ';'

plot indata1 using 1:2 with linespoints lw 2 title 'BBs', \
     indata1 using 1:3 with linespoints lw 2 title 'edges'

replot
pause -1
