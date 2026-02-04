# Fuzzing with Hardware-in-the-Loop

This page summarizes practical guidance for fuzzing a target that interacts with
real hardware during execution. The device becomes part of the fuzzing loop,
which has direct implications on coverage and snapshotting reliability.

```{mermaid}
flowchart TD
  A[Start] --> B{Reset reliable?}
  B -- Yes --> C[Snapshots possible]
  B -- No --> D[Disable snapshots]
  C --> E{Snapshot placement}
  E -- Before driver init --> F[Pre-init snapshot]
  E -- After driver init --> G[Post-init snapshot]
```

## 1. Reset reliable

Reliable reset means that after each reset:

- The device and driver return to a known-good state.
- The same test case produces the same observable behavior and coverage.
- The device consistently accepts new work without timeouts or error storms.




:::{warning}
Large stateful devices (for example GPUs) often keep significant internal micro-architectural state that is not fully cleared
by a device-level reset.

In practice, a full platform reboot may be required to restore a clean baseline.
:::

If we **assume** the device can be reset to a known-good state between inputs, you can use
snapshots with two placements:

### 1.1 Pre-init snapshot

```{mermaid}
flowchart TD
  A[System init] --> B[kAFL snapshot]
  B --> C[Driver init]
  C --> D[Harness start]
  D --> E[Execute test case]
  E --> F[Harness stop]
  F --> B
```

- Restore to a pre-driver state.
- Let the driver enumerate and initialize the device each iteration.
- **Slower** but tends to be more **robust** for complex devices.


### 1.2 Post-init snapshot

```{mermaid}
flowchart TD
  A[System init] --> B[Driver init]
  B --> C[kAFL snapshot]
  C --> D[Device reset]
  D --> E[Re-establish configured state]
  E --> F[Harness start]
  F --> G[Execute test case]
  G --> H[Harness stop]
  H -- Next input --> C
```

- Restore to a post-init guest state (driver already loaded), then reset and
  re-arm the device each iteration.
- Keeps the expensive vendor driver initialization path out of the snapshot
  loop.
- Faster per iteration, but only works if you can reset and re-arm the
  device/driver state in a cheaper, deterministic way between inputs.

## 2. Reset unreliable

If the reset is not reliable, you can still leverage kAFL and **disable snapshot mode** entirely.
This is closer to a syzkaller-style campaign: no reset between inputs, high
throughput, and unavoidable state drift with lower determinism.

### 2.1 Coverage: prefer software instrumentation

Without snapshotting, the VM memory state will start to drift over time.
Intel PT relies on a stable guest memory layout and a page-cache based model. If
memory drifts and snapshots are disabled, PT decoding can stall or miss
execution, which effectively makes coverage unusable.

When possible, **use KCOV or other software instrumentation** as the authoritative
coverage source, and treat PT as best-effort.



### 2.2 Non-determinism and feedback noise

With hardware in the loop, you must assume a non-deterministic system. The
biggest risk is that the device (or its driver) hangs and the target starts
returning errors for everything. At that point:

- Coverage stops changing, so inputs look "uninteresting" and are discarded.
- The original crashing or hanging input may fail validation because replays
  follow a different path (for example, immediate driver errors).

## Caveats

DMA is asynchronous. A test case can submit DMA work that completes later, so
its memory writes may land during the next iteration and contaminate feedback.
Before accepting the next input, ensure outstanding DMA has quiesced, or reset
and re-arm strongly enough that no previous DMA completion can leak across
iterations.
