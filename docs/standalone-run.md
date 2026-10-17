# Standalone run (no host listener)

The `standalone` build variant is designed to run the exploit **without a
Macbook in the loop** after the ELF is uploaded:

- no USB log file (`PXEL_NO_USB`);
- stdout is **non-blocking** (`PXEL_STANDALONE`) — a missing or dead host
  socket can never wedge the payload; lines are simply dropped;
- every verdict is delivered as an **on-screen notification** on the
  console, so the run is fully observable without any host.

## Build

```sh
make standalone
# -> build/standalone/byepv-pxl-v<VERSION>.elf
```

## Run

1. Get the console into the state where elfldr (or any ELF loader you
   trust) listens — e.g. run the relapse chain.
2. Upload the standalone ELF by any means (the loader protocol is raw
   bytes + `SHUT_WR`):

   ```sh
   nc -q0 10.10.10.2 9021 < build/standalone/byepv-pxl-v0.1.0.elf
   ```

   (any host is fine; you may disconnect the ethernet afterwards)
3. Watch the **console screen** for notifications:
   - `Byepervisor-pxl / 11.60 hook armed, enter sleep and resume!`
   - put the console into rest mode, then wake it;
   - on success: `Byepervisor Reborn 11.60 - SUCCESS ...`
   - on failure: a `[ERROR]` notification with the reason
     (e.g. `11.60 hook arm failed :(`).

## What you lose vs. the debug variant

- no line-by-line log (stream lines are best-effort and drop when the
  socket is gone);
- no USB log file;
- no previous-log dump.

The authoritative success proof is the on-screen notification (it is sent
only after the in-kernel result blocks verify 16/16).
