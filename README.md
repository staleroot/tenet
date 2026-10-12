# Tenet — FRINET fork

<p align="center">
<img alt="Tenet Trace Explorer" src="screenshots/tenet_overview.gif"/>
</p>

> **This is the IDA plugin that ships with
> [FRINET](https://github.com/staleroot/frinet).**
>
> It is a fork of [gaasedelen/tenet](https://github.com/gaasedelen/tenet) with
> the FRINET additions: the `.frinet` trace format, synchronised Hex-Rays
> pseudocode, and new dockable panels. It still reads legacy `.tenet` traces,
> so it can replace a stock Tenet installation outright.
>
> If you want the **tracer** as well as the plugin, clone FRINET recursively —
> do not clone this repository on its own:
>
> ```
> git clone --recursive https://github.com/staleroot/frinet.git
> ```

Tenet is an [IDA Pro](https://www.hex-rays.com/products/ida/) plugin for
exploring execution traces. The goal is natural, human controls for navigating
execution against a given binary — stepping through time, following the
instruction pointer, and asking *"where was this byte read?"* and *"what set
this register?"* without leaving the disassembler.

For context on the original project, read the
[ Tenet blogpost](http://blog.ret2.io/2021/04/20/tenet-trace-explorer/).
For the FRINET additions, read the
[Synacktiv blogpost](https://www.synacktiv.com/publications/frinet-reverse-engineering-made-easier).

---

## Contents

* [What this fork adds](#what-this-fork-adds)
* [Installation](#installation)
* [Loading a trace](#loading-a-trace)
* [FRINET additions in detail](#frinet-additions-in-detail)
  * [Pseudocode synchronisation](#pseudocode-synchronisation)
  * [Event Info panel](#event-info-panel)
  * [Registers and memory](#registers-and-memory)
  * [Addressing](#addressing)
* [Tenet usage guide](#tenet-usage-guide)
  * [Bidirectional exploration](#bidirectional-exploration)
  * [Trace timeline](#trace-timeline)
  * [Execution breakpoints](#execution-breakpoints)
  * [Memory breakpoints](#memory-breakpoints)
  * [Region breakpoints](#region-breakpoints)
  * [Register seeking](#register-seeking)
  * [Timestamp shell](#timestamp-shell)
  * [Themes](#themes)
* [Supported versions](#supported-versions)
* [Debugging](#debugging)
* [Testing](#testing)
* [FAQ](#faq)
* [Provenance](#provenance)

---

## What this fork adds

On top of upstream Tenet:

| Addition | |
|---|---|
| **`.frinet` trace format** | A `slide=` header and a per-event `off=` field, so navigation is driven by the module offset instead of a runtime address that ASLR has already moved. |
| **Hex-Rays pseudocode synchronisation** | The decompiled view follows the trace, highlighting the most precise expression it can find — not just the line. |
| **Event Info panel** | Index, thread, `pc`, `off`, `static_ea`, mapped status, pseudocode precision, and the registers/memory that changed — all copyable. |
| **Register view** | Hexadecimal/decimal toggle and base-aware copy. |
| **arm64 / arm support** | The tracer is architecture-agnostic; these were mostly free. |
| **Call tree view** | A clickable indented overview of the whole execution trace. |
| **Search bytes** | From the memory view context menu — a pattern search across space *and* time. |
| **Multiple memory views**, plus more context-menu options | |
| **Minor fixes** and small design modifications | |

<img alt="FRINET" src="https://raw.githubusercontent.com/staleroot/frinet/main/screenshots/frinet.png"/>

*The call tree view (bottom left) and search bytes are both visible.*

**Removed for now:** the compressed trace format (`.tt`). It has to be
rewritten to handle the added fields. This and the behavioural changes above
are why this fork is not currently a pull request upstream — it will be, when
the legacy features are reintroduced and the changes are better tested across
IDA versions.

---

## Installation

The plugin is pure Python and takes **zero third-party dependencies**.

1. Clone FRINET with the submodule (see the banner above).

2. From IDA's Python console, find the plugin directory:

   ```python
   import idaapi, os; os.path.join(idaapi.get_user_idadir(), "plugins")
   ```

3. Copy this repository's `/plugins/` contents into that directory:

   ```
   cp tenet/plugins/tenet_plugin.py <IDA>/plugins/
   cp -R tenet/plugins/tenet       <IDA>/plugins/
   ```

4. Restart IDA.

---

## Loading a trace

With the matching binary open:

```
File -> Load file -> Tenet / FRINET trace
```

The file dialog lists **both** `*.frinet` and `*.tenet`. Legacy traces have no
`off=` fields, so the plugin falls back to an ASLR-slide heuristic and the
Event Info panel says so explicitly rather than pretending the translation is
exact.

<p align="center">
<img alt="Load Tenet trace" src="screenshots/load_trace.gif"/>
</p>

---

## FRINET additions in detail

### Pseudocode synchronisation

The disassembly has always followed the trace. This fork makes the
**decompiled view follow it too**.

```
static_ea = idb_module_start + off  ->  ctree item  ->  rendered line + column
```

* **Five explicit precision levels** — `expr` → `item` → `line` → `nearest` →
  `none` — and the level used is *reported*, so an approximate highlight never
  looks like an exact one.
* **No guessing.** Events without an `off=`, and addresses outside the traced
  module, are never mapped into the pseudocode.
* **Responsive while scrubbing.** Coalesced updates, stale-result rejection,
  bounded LRU caches, and prefetch that never forces a decompilation you did
  not ask for. Every IDA and Hex-Rays call runs on the main thread.

The view is only ever *followed*, never invented out from under you. A window
already showing the traced function is used as it is; one open on a different
function is **retargeted** (so a single window follows the trace rather than
the trace dropping a window per function); and a window you deliberately
closed is reopened at most once, then left closed.

Set `TENET_NO_PSEUDOCODE_OPEN=1` to disable auto-open entirely.

> **IDA 9.4 note.** The cursor is placed by cloning the view's own place —
> every `*place_t` class on recent builds is abstract, so a place cannot be
> constructed, but it can be cloned and the clone retargeted. If the cursor
> ever stops moving, set `TENET_DEBUG=1` and the `pseudocode jump …` line
> names every attempt and every refusal.

### Event Info panel

Dockable, next to the CPU Registers. For the selected event it shows:

| Row | |
|---|---|
| index / thread | position in the trace, and which thread's file it came from |
| `pc` | the instruction pointer exactly as executed |
| `off` | `pc - slide`, present only for in-module events |
| `static_ea` | `idb_module_start + off` — where it lives in the open IDB |
| mapped | whether the database actually contains that address |
| precision | which of the five levels the pseudocode sync used |
| registers | which registers changed at this event |
| memory | bytes read and written at this event |

Values are copyable; the address row is navigable.

### Registers and memory

The register view gains a **hex/decimal toggle** and base-aware copy. A
register with **no recorded value** renders as `?` and copies nothing — it is
never shown or copied as `0`.

The memory views read **exclusively from the trace**. They never fall back to
live process memory or to the IDB's static bytes, because either would
fabricate a history the trace does not contain. Unrecorded bytes render as
`??`, which is the truth.

### Addressing

Four values are kept distinct throughout, and confusing any pair of them
produces confidently wrong navigation:

| Term | Meaning |
|---|---|
| `pc` | the instruction pointer as executed on the device |
| `slide` | the traced module's runtime base (the `slide=` header) |
| `off` | `pc - slide`, defined only inside the traced module |
| `static_ea` | `idb_module_start + off` — the address in the open IDB |

`off` is the primary navigation key. `idb_module_start` is derived from the
database's **real segment layout**, not from `get_imagebase()`, which is wrong
exactly often enough to matter on rebased or stripped Android images. When the
evidence is genuinely ambiguous the plugin asks rather than guessing.

---

## Tenet usage guide

Everything below is upstream Tenet behaviour and still applies unchanged.

### Bidirectional exploration

While using Tenet, the plugin paints trails to indicate the flow of execution
forwards (blue) and backwards (red) from your present position.

<p align="center">
<img alt="Tenet trails" src="screenshots/tenet_trails.gif"/>
</p>

To `step` forwards or backwards through time, **scroll while hovering over the
timeline** on the right side of the disassembler. To `step over` function
calls, hold `SHIFT` while scrolling.

### Trace timeline

The trace timeline is docked on the right side of the disassembler and
visualises different types of events along the trace.

<p align="center">
<img alt="Zooming in on the trace timeline" src="screenshots/trace_zoom.gif"/>
</p>

**Clicking and dragging across the timeline** zooms in on a section. Repeat it
as many times as you need to reach the desired granularity.

### Execution breakpoints

Double click the instruction pointer in the registers window to highlight it
in red — revealing every location that instruction executed across the trace.

<p align="center">
<img alt="Placing a breakpoint on the current instruction" src="screenshots/trace_breakpoints.gif"/>
</p>

To jump between executions, **scroll up or down while hovering the highlighted
instruction pointer**.

You can also right click in the disassembly listing and select one of the
navigation entries to seek to an instruction of interest.

<p align="center">
<img alt="Seeking to the first execution of an instruction" src="screenshots/seek_to_first.gif"/>
</p>

IDA's native `F2` hotkey sets breakpoints on arbitrary instructions.

### Memory breakpoints

Double click a byte in either the stack or memory views to see all reads and
writes to that address across the timeline. **Yellow** is a memory *read*,
**blue** is a memory *write*.

<p align="center">
<img alt="Exploring memory accesses using memory breakpoints" src="screenshots/memory_breakpoint.gif"/>
</p>

Navigate them the same way as execution breakpoints: double click a byte, then
**scroll while hovering the selected byte** to seek to each of its accesses.

Right clicking a byte gives you direct seek options for read / write / access.

<p align="center">
<img alt="Memory seeking" src="screenshots/memory_seek.png"/>
</p>

To navigate a memory view to an arbitrary address, click into it and hit `G`
to enter an address or a database symbol.

### Region breakpoints

Highlight a block of memory and double click it to set an access breakpoint
across that whole region.

<p align="center">
<img alt="Memory region access breakpoints" src="screenshots/region_breakpoints.gif"/>
</p>

As with normal memory breakpoints, hovering the region and **scrolling**
traverses the accesses made to it.

### Register seeking

Reverse engineering constantly asks *"which instruction set this register to
its current value?"* Tenet answers it in a single click.

<p align="center">
<img alt="Seeking to the previous register write" src="screenshots/seek_to_register.gif"/>
</p>

Seeking **backwards** is by far the common direction, but the blue arrow on the
right of a register seeks forward to the next assignment.

### Timestamp shell

A simple shell for navigating to specific timestamps. Paste or type a
timestamp, with or without commas.

<p align="center">
<img alt="Seeking around the trace using the timestamp shell" src="screenshots/idx_shell.gif"/>
</p>

With an exclamation point you can seek a **percentage** into the trace: `!100`
goes to the final instruction, `!50` roughly halfway. `!last` goes to the last
navigable instruction.

### Themes

Tenet ships with a light and a dark theme and picks whichever suits the
disassembler's current colors.

<p align="center">
<img alt="Tenet Themes" src="screenshots/themes.png"/>
</p>

Themes are plain JSON on disk and highly configurable — drop your own into the
user theme directory. The preference is remembered across loads.

---

## Supported versions

| | |
|---|---|
| **IDA Pro 9.4** | Primary target, with Hex-Rays. |
| IDA Pro 8.x | Loads; the existing `8.+`/`9.+` compatibility paths are preserved. |
| IDA Pro 7.5+ | The floor inherited from upstream Tenet. |
| **Hex-Rays** | Required for pseudocode synchronisation only. Without it the plugin loads and traces are fully browsable. |
| Qt bindings | IDA ≤ 9.1 ships Qt5/PyQt5, IDA 9.2+ ships Qt6/PySide6. The shim uses whichever binding the host already loaded and normalises the Qt6 class moves, so the same code works on both. PySide2 is also accepted. |

---

## Debugging

Two switches, answering different questions:

| Variable | Where it goes | Answers |
|---|---|---|
| `TENET_DEBUG` | IDA's **output window** | "what is the plugin deciding, right now?" |
| `TENET_DEV` | `tenet_logs/tenet.<pid>.log` | "what did the plugin do, overall?" |
| `TENET_NO_PSEUDOCODE_OPEN` | — | Not a logging switch: changes what sync *does* (see above). |

```
set TENET_DEBUG=1
"C:\Program Files\IDA Professional 9.4\ida.exe"
```

Restart IDA after setting it — the plugin reads it once at import. The full
message legend is in the
[FRINET README](https://github.com/staleroot/frinet#debugging).

---

## Testing

The automated tests live in the **parent repository**, not here:

```
git clone --recursive https://github.com/staleroot/frinet.git
cd frinet && python3 -m pytest tests/ -q
```

305 pass without a Qt binding (306 with PySide6); the rest skip. They cover
trace parsing, the `.frinet` conversion, address resolution, the
synchronisation controller and cursor navigation — all with fakes. **They
require no IDA, no Qt binding and no device, and they claim nothing about a
live IDA session.**

Everything that needs a real IDA is covered by a separate manual procedure in
[`docs/manual-testing.md`](https://github.com/staleroot/frinet/blob/main/docs/manual-testing.md).

---

## FAQ

**Tenet is a trace reader, not a recorder.** You need a dynamic binary
instrumentation framework (or similar) to generate a compatible trace. The
[Frida tracer in FRINET](https://github.com/staleroot/frinet#tracer) is the
one this fork is written for.

**Which architectures?** The reader is architecture-agnostic. FRINET's tracer
fully supports `arm64` and `x64`, with partial support for `arm` and `x86`.

**How large a trace?** The trace reader is pure Python and was written as an
MVP. There is no guarantee that traces beyond ~10 million instructions navigate
reasonably until a native backend replaces it. Note that this fork also removed
upstream's compressed `.tt` cache, so every load re-parses the text trace.

**Memory is changing in my trace, but there are no writes to that region.**
Your log file may not have captured every memory write — usermode DBI generally
gets no callback for kernel writes into your buffer (reading from a file or a
socket, for example). Microsoft TTD behaves the same way unless syscalls are
modelled.

**The plugin crashed or is showing bad trace information.** Please file an
issue with a sample trace and the executable. If the plugin misbehaves inside
IDA, a `TENET_DEBUG=1` output window plus the IDB's image name is usually
enough to localise it.

---

## Provenance

**[Tenet](https://github.com/gaasedelen/tenet)** was written by
[Markus Gaasedelen](https://twitter.com/gaasedelen). The original README's
usage documentation is preserved above (reorganised, and updated where
behaviour in this fork differs). Special thanks to
[QIRA](https://github.com/geohot/qira) / [geohot](https://twitter.com/realGeorgeHotz)
for the inspiration.

**[FRINET](https://github.com/synacktiv/frinet)** — the tracer, the trace
format and the plugin extensions — is by
[Synacktiv](https://www.synacktiv.com/).

This repository is **staleroot's** maintained fork of both. It is not
submitted upstream yet: the new features break some legacy Tenet behaviour
(the compressed trace format is removed for now), and it will be PR'd once
those are restored and the changes are better tested across IDA versions.

MIT licensed — see [LICENSE](LICENSE).
