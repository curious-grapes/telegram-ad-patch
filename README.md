# Telegram Desktop sponsored-message patcher

Binary patcher for **Telegram.exe (Windows x64)** that stops channel sponsored
messages, without recompiling. Verified against **v7.3.3** and **v7.4.6**; it
re-derives every location on each run, so it is built to tolerate future
minor updates (and refuses rather than mis-patching if a site truly changes).

## Run

```
python patcher.py
```

GUI: pick `Telegram.exe`, choose a mode with the radio buttons
(**Display gate** / **Network source** / **Both**), then **Locate / preview**
(no writes) or **Patch**. **Restore from backup…** reverts.

Headless:
```
python patcher.py --locate  <Telegram.exe>
python patcher.py --patch   both <Telegram.exe>     # display | network | both
python patcher.py --restore <Telegram.exe>
```

A prebuilt `dist/TelegramSponsoredPatcher.exe` (no Python needed) is also
provided. Requires `pefile` + `capstone` when run from source. **Close Telegram
before patching.**

## What gets patched and why

`Data::SponsoredMessages::canHaveFor()` — the source-level gatekeeper — is
**fully inlined** in release builds (whole-program optimization emits no
standalone copy), so it cannot be flipped as a single function. Instead there
are two independent choke points, applied independently: if one cannot be
resolved on a given build, the other is still applied.

### Display gate  (`xor eax,eax ; ret`, bytes `31 C0 C3`)
The per-view "should this peer show sponsored messages?" predicate. It checks
channel type, the channel's `restricted_sponsored` flag, Premium, and a few
exempt channel IDs; its callers do `test al,al ; je (skip sponsored)`. Forcing
it to **false** means a channel is never eligible, so nothing is displayed.
Pure boolean → completely safe.

Located by a wildcarded byte signature anchored on the `0x2000` ads-flag test
and the `shr reg,0x30 ; cmp …,2` channel-type idiom. Relocatable struct offsets
are wildcarded, which is why it survived the peer-offset change `0xD8 → 0x108`
between 7.3.3 and 7.4.6. Must match **exactly once** or it is skipped.

### Network source  (enqueue `call` → 5× `NOP`)
The client never sends `messages.getSponsoredMessages`, so sponsored messages
are never fetched. The MTProto enqueue `call` in the request serializer is
replaced with NOPs; the serializer still runs its cleanup, so nothing leaks.

Resolved from invariants, not offsets:
TL constructor id **`0x3D6CE850`** → its writer function → the writer's
caller (the serializer) → the one direct `call` set up with the request id in
`EDX` and the api instance in `RCX` (the enqueue calling convention). This is
register/offset independent, so it moved cleanly from `0x01503FAA` (7.3.3) to
`0x01614C92` (7.4.6) with no change to the patcher.

## Safety / behavior
- Always makes a timestamped backup (`Telegram.exe.<ts>.bak`) before writing.
- Each site must resolve uniquely; anything ambiguous is skipped, not guessed.
- Re-running on an already-patched file is detected (no double-patch), including
  the NOP'd network site.
- Nothing else is touched — updater, networking and code signing are untouched.

## Risks / caveats
- **Auto-update overwrites the patch.** After Telegram updates itself, just run
  the patcher again — it re-finds the sites on the new build.
- **The Authenticode signature becomes invalid** once the exe is modified.
  Telegram still runs; environments that enforce signature checks may not.
- "Future-proof" means *resilient*, not guaranteed: a major rewrite of the
  sponsored code could move a site beyond the signature's tolerance, in which
  case the patcher reports it as not resolved instead of patching the wrong
  place. Then the signatures need a quick re-derivation.
- Patch your own copy. This modifies a GPLv3 program locally for personal use.
