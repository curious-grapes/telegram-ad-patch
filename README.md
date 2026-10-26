# Telegram Desktop sponsored-message patcher

Binary patcher for **Telegram.exe (Windows x64)** that stops channel sponsored
messages, without recompiling. Built and verified against **v7.3.3** (the
installed version), source cross-referenced at tag `v7.3.3`.

## Run

```
python patcher.py
```

GUI: pick `Telegram.exe`, choose a patch mode with the radio buttons
(**Display gate** / **Network source** / **Both**), then **Locate / preview**
(no writes) or **Patch**. **Restore from backup…** reverts.

Headless:
```
python patcher.py --locate  <Telegram.exe>
python patcher.py --patch both <Telegram.exe>     # display | network | both
python patcher.py --restore <Telegram.exe>
```

Requires `pefile`; `capstone` is optional (used only to pretty-print the patched
instructions). Close Telegram before patching.

## What gets patched and why

`Data::SponsoredMessages::canHaveFor()` — the source-level gatekeeper — is
**fully inlined** in this release build (whole-program optimization emitted no
standalone copy), so it cannot be patched as a single function. Instead there
are two independent, equally valid choke points:

### Display gate  (`xor eax,eax ; ret`, bytes `31 C0 C3`)
The per-view "should this peer show sponsored messages?" predicate
(`RVA 0x01f84070` in v7.3.3). It checks channel type, the channel's
`restricted_sponsored` flag, Premium, and a few exempt channel IDs; its callers
do `test al,al ; je (skip sponsored)`. Forcing it to return **false** means a
channel is never eligible, so nothing is displayed. Pure boolean → completely
safe, no side effects.

Found by a wildcarded byte signature (the `restricted_sponsored` 0x2000 flag
test plus the `shr reg,0x30 ; cmp …,2` channel-type idiom); relocatable struct
offsets are wildcarded. Must match **exactly once** or it aborts.

### Network source  (enqueue `call` → 5× `NOP`)
The client never sends `messages.getSponsoredMessages`, so sponsored messages
are never fetched. The MTProto enqueue call inside the request serializer
(`RVA 0x01503faa`) is replaced with NOPs; the serializer still runs its own
epilogue and frees the moved callback objects, so **no leak**.

Located from the stable protocol constant rather than a fragile offset:
TL constructor id **`0x3D6CE850`** (`messages.getSponsoredMessages`) → its
writer function → the writer's unique caller (the serializer) → the enqueue
call inside it. Must resolve to **exactly one** site or it aborts.

## Safety / behavior
- Always makes a timestamped backup (`Telegram.exe.<ts>.bak`) before writing.
- Signatures are match-once; anything ambiguous aborts without touching the file.
- Re-running on an already-patched file is detected (no double-patch).
- Nothing else is touched — updater, networking and code signing are untouched.

## Risks / caveats
- **Auto-update will overwrite the patch.** After Telegram updates itself you
  must re-run the patcher (the signatures are designed to survive minor updates,
  but a rebuilt binary may move or change the sites).
- **The Authenticode signature becomes invalid** once the exe is modified.
  Telegram still runs; some environments that enforce signature checks may not.
- These patches are version-matched to v7.3.3. On another version the patcher
  re-resolves by signature/constant; if it can't match uniquely it refuses
  rather than guessing.
