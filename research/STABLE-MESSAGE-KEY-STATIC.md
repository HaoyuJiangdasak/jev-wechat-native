# UIMessage stable key: static evidence

Target: Weixin 4.1.15.11 (`Weixin.dll`, SHA-256
`7d056cf7fb834b5558d6646bfb4e0036aae93568e3f9a04cf1dfc5e79032bcac`).
This note is based on disassembly only; no process was attached and no chat
content, database, or key was read.

## Canonical string fallback

`0x7B9000` is a two-instruction leaf:

```asm
lea rax, [rcx + 0x98]
ret
```

Its caller `0x227A000(UIMessage*, temp)` copies the returned MSVC string
(`msg + 0x98`) into `temp + 0x30`, with size at `temp + 0x40` and capacity at
`temp + 0x48`.

## Composite key construction

`0x227A000` also copies these fields into its temporary record:

| temporary | source | use |
| --- | --- | --- |
| `+0x00` | `msg + 0x70` | conversation string |
| `+0x20` | `msg + 0xD0` | 32-bit seconds field |
| `+0x24` | `msg + 0x94` | 32-bit sequence field |
| `+0x28` | `msg + 0xC8` | timestamp value used by display-time code |

`0xA17360(temp, out)` then behaves as follows:

1. When `temp + 0x24 != 0`, it emits `conversation + "_" + decimal(seconds) + "_" + decimal(sequence)`.
2. When the sequence is zero and the copied fallback string is non-empty, it copies that fallback (`msg + 0x98`) to the output.
3. When both the sequence and fallback are empty, it still emits `conversation + "_" + decimal(seconds) + "_0"`.

The underscores and decimal conversion are visible in the instruction stream
(`0xA174C6`, `0xA176CA`, and the two base-10 conversion loops).

## Safe consumer rule

For a read-only adapter, first require the existing identity checks: the
message at `binding + 0x120` must have a non-empty `msg + 0x70` that equals
`listener + 0xA0`; reject the row when this fails. Then reproduce the key
above without calling any native string-mutating routine. Keep a set of keys
seen in the active conversation; a row is eligible for a new analysis only if
its key is unseen and the sender classification says `her`. This prevents a
virtualized row rebinding to an old message from triggering a second analysis.

The key is an ordering/identity key used by native UI code. The static evidence
does not establish that `msg + 0x94` is a server-global sequence, so do not
expose it as one. `msg + 0xD0` is seconds and is suitable only as part of the
composite key or as coarse chronology.

## Timestamp boundary

`0xA17160` forwards ordinary fields `msg + 0xC8` and `msg + 0xD0` to
`0xA1D4F0`. `0xA1D4F0` checks feature flag
`clicfg_xwechat_message_ui_timestamp`; it uses `msg + 0xC8 / 1000` only when
the flag is enabled and the value exceeds `1293811200000` (2011-01-01 ms),
otherwise it uses `msg + 0xD0`. Timestamp comparison can order messages but
must not replace the composite key for de-duplication.

Evidence files:

- `layout-disassembly-7b9000.json`
- `layout-disassembly-227a000-a17360.json`
- `layout-disassembly-a1d4f0-3e3a0f0-3ee6200.json`

