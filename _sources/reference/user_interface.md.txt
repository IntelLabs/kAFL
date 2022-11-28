# kAFL User Interface

## kAFL GUI

The `kafl_gui.py` renders the various status and metadata files of a workdir
into a curses based text UI. You can also use it on an old / archived workdir to
obtain a quick overview of the campaign status and average performance:

    $ kafl_gui.py /path/to/workdir
    
      ┏━┫▌kAFL Grand UI▐┣━┓
    ┏━┻━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃ Runtime:    2h00m │ #Execs:     26.0M │ Stability:     0% │ Workers:   16/72 ┃
    ┃                   │ CurExec/s:   4018 │ Funkiness:   0.0% │ CPU Use:      0% ┃
    ┃ Est. Done:    74% │ AvgExec/s:   3616 │ Timeouts:    0.0% │ RAM Use:      1% ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    ┏━━❮❰ Progress ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                                                              ┃
    ┃ Paths:            │ Bitmap:           │ Findings:                            ┃
    ┃  Total:       141 │                   │  Crash:           4 (N/A)      1h57m ┃
    ┃  Seeds:        45 │  Edges:     11.1K │  AddSan:          1 (N/A)      1h57m ┃
    ┃  Favs:         18 │  Blocks:    21.2K │  Timeout:         9 (N/A)     13m15s ┃
    ┃  Norm:        123 │  p(col):     8.4% │  Regular:       141 (N/A)      3m27s ┃
    ┠──────────────────────────────────────────────────────────────────────────────┨
    ┃ Yld: Init:     38 │ Grim:      0 │ Redq:      6 │ Det:      0 │ Hvc:      66 ┃
    ┃ Fav: Init:      0 │ Rq/Gr:     0 │ Det:       6 │ Hvc:      0 │ Fin:      12 ┃
    ┃ Nrm: Init:      0 │ Rq/Gr:     0 │ Det:       1 │ Hvc:      2 │ Fin:     120 ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    ┏━━❮❰ Activity ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                                                              ┃
    ┃ >Worker  0:    afl_splice │ node:   140 │ fav/lvl:     0/  2 │ exec/s:   399 ┃
    ┃  Worker  1:     afl_havoc │ node:     1 │ fav/lvl:    97/  0 │ exec/s:   395 ┃
    ┃  Worker  2:  afl_flip_2/1 │ node:    96 │ fav/lvl:     5/  2 │ exec/s:   400 ┃
    ┃  Worker  3:    afl_splice │ node:   106 │ fav/lvl:     0/  2 │ exec/s:   371 ┃
    ┃  Worker  4:    afl_splice │ node:    85 │ fav/lvl:     0/  1 │ exec/s:   243 ┃
    ┃  Worker  5:  afl_flip_2/1 │ node:   103 │ fav/lvl:     1/  1 │ exec/s:   244 ┃
    ┃  Worker  6:    afl_splice │ node:    58 │ fav/lvl:     0/  1 │ exec/s:   245 ┃
    ┃  Worker  7:  afl_flip_2/1 │ node:    62 │ fav/lvl:    25/  1 │ exec/s:   242 ┃
    ┃  Worker  8:       radamsa │ node:    50 │ fav/lvl:     0/  1 │ exec/s:    32 ┃
    ┃  Worker  9:    afl_splice │ node:   153 │ fav/lvl:     0/  2 │ exec/s:   233 ┃
    ┃  Worker 10:  afl_flip_2/1 │ node:    84 │ fav/lvl:    20/  1 │ exec/s:   245 ┃
    ┃  Worker 11:  afl_flip_2/1 │ node:    99 │ fav/lvl:     1/  2 │ exec/s:   243 ┃
    ┃  Worker 12:  afl_flip_2/1 │ node:    30 │ fav/lvl:     0/  0 │ exec/s:   239 ┃
    ┃  Worker 13:    afl_splice │ node:    64 │ fav/lvl:     0/  1 │ exec/s:   241 ┃
    ┃  Worker 14:    afl_splice │ node:   146 │ fav/lvl:    27/  2 │ exec/s:   240 ┃
    ┃  Worker 15:   afl_arith_2 │ node:    21 │ fav/lvl:     1/  0 │ exec/s:     6 ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    ┏━━❮❰ Node Info ❱❯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                                                              ┃
    ┃ Id:   140 │ Size:   1.0KB │ Perf:   4.75ms │ Score:      3 │ Fuzzed:   0h02m ┃
    ┠──────────────────────────────────────────────────────────────────────────────┨
    ┃ 0x0000000: 17 45 9d e4 47 90 50 f5 52 61 59 7c dd e4 ac 8e │.E..G.P.RaY|.... ┃
    ┃ 0x0000010: 8c 86 b0 92 77 fb 28 f0 4c f7 23 49 75 12 94 14 │....w.(.L.#Iu... ┃
    ┃ 0x0000020: d5 76 1b 15 66 5b 52 9e e7 c6 10 91 51 6d 35 40 │.v..f[R.....Qm5. ┃
    ┃ 0x0000030: 80 8d ad 1a fe b4 22 a0 20 72 b0 f0 f5 a4 89 4f │......". r.....O ┃
    ┃ 0x0000040: ef 9d ea 6a b2 26 21 7a bc fa 79 1a f9 ac d1 da │...j.&!z..y..... ┃
    ┃ 0x0000050: 94 dd 25 3b e7 58 63 79 93 1e c7 ad 93 dd 14 41 │..%;.Xcy.......A ┃
    ┃ 0x0000060: 9d 51 cb e7 1f f9 df 3a ea 98 31 37 30 31 34 31 │.Q.....:..170141 ┃
    ┃ 0x0000070: 31 38 33 34 36 30 34 36 39 32 33 31 37 33 31 36 │1834604692317316 ┃
    ┃ 0x0000080: 38 37 33 30 33 83 41 ef 60 ea e4 c0 28 72 23 68 │87303.A.`...(r#h ┃
    ┃ 0x0000090: 58 f4 84 8d 58 8e f5 70 60 00 27 3a 71 cb 46 51 │X...X..p..':q.FQ ┃
    ┃ 0x00000a0: f2 cf f9 51 1d 81 31 2c f6 37 3e 5e 67 15 30 80 │...Q..1,.7>^g.0. ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

The UI is split into 4 windows, with increasingly detailed status indicators:

1. Campaign Performance 

   - Runtime: total elapsed time
   - Est. Done: current progress estimate (very rough)

   - #Execs: total number of executions
   - CurExec/s: Sum of current exec/s reported by each worker
   - AvgExec/s: Total executions per second (`= #execs / runtime`)

   - Stability: Overall fraction of executions which are crashing or timing out.
     Watch this for frequent/shallow crashes or timeouts and adjust your setup.
   - Funkiness: Fraction of non-deterministic executions (see `--funky`)
   - Timeouts: Fraction of executions which are timing out

   - Workers: Number of workers launched vs. available vCPUs.
   - CPU Use: Current CPU usage
   - RAM Use: Current RAM usage

2. Campaign Progress

   Paths: Unique payloads in the queue
   - Total: Total `regular` (not crashing, not timeout) inputs
   - Seeds: Fraction of inputs learned via `--seed-dir` or `--kickstart`
   - Favs/Norms: Number of `favorite` vs. `normal` inputs

   Bitmap: Coverage / feedback bitmap status
   - Edges: Number of block transitions discovered (bytes in `regular` bitmap)
   - Blocks: Number of basic blocks seen by PT tracer (*all* execution types)
   - p(col): Probability of hash collision in bitmap (see `--bitmap-size`)

   Findings: Unique payloads (based on bitmap) and time since last find
   - Crash: Executions returning with PANIC or PANIC_EXTENDED hypercall
   - AddSan: Executions returning with KASAN hypercall
   - Timeout: Executions intercepted by Qemu timeout
   - Regular: Executions returning with RELEASE hypercall

   - Yld: Yield, i.e. the number of unique inputs found by individual
     mutation/stages (init, grimoire, redqueen, deterministic, havoc).
   - Fav: Number of `favorite` payloads in respective mutation stage (new
     findings start in `init` and iteratively progress through to `fin`).
   - Nrm: Number of `normal` payloads in respective mutation stage (traverse
     through mutation stages at lower priority compared to favorites)

3. Worker Activity

   Currently scheduled task at each worker (select with Up/Down):
   - worker ID
   - active mutation
   - scheduled node (payload ID)
   - fav/lvl: number of favorite bits and level of the payload
   - exec/s: current execution speed for this payload/mutation

4. Payload Detail

   Addition detail on payload scheduled by selected worker:
   - Payload id, size, execution speed (perf), assigned score
   - Fuzzed: Total time this payload has been mutated/processed by a worker

