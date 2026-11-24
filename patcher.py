#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Desktop (Windows x64) sponsored-message patcher.

Two independent patches for channel sponsored messages. Nothing is tied to a
fixed file offset; every location is re-derived on each run from version-stable
invariants and must resolve unambiguously, or that patch is skipped (the other
is still applied).

  DISPLAY GATE  - Neutralizes the per-view "should this peer show sponsored
                  messages?" predicate so it always returns false. Patch: the
                  function entry becomes `xor eax,eax ; ret` (31 C0 C3). Pure
                  boolean, no side effects. Located by a wildcarded byte
                  signature (the `restricted_sponsored` 0x2000 flag test plus
                  the `shr reg,0x30 ; cmp …,2` channel-type idiom); relocatable
                  struct offsets are wildcarded, so it tolerates field moves
                  (e.g. the peer offset changed 0xD8 -> 0x108 between 7.3.3 and
                  7.4.6 and the signature still matched).

  NETWORK SOURCE- Stops the client from ever sending
                  `messages.getSponsoredMessages`, so channel sponsored
                  messages are never fetched. The MTProto enqueue `call` in the
                  request serializer is replaced with NOPs; the serializer still
                  runs its cleanup, so no object is leaked. Located from the
                  stable TL constructor id 0x3D6CE850 -> its writer function ->
                  the writer's caller(s) (the serializer) -> the one direct call
                  made with the request-id in EDX and the api instance in RCX
                  (the enqueue calling convention, which is register/offset
                  independent).

Requires: Python 3, pefile, capstone.

GUI:   python patcher.py
CLI:   python patcher.py --locate  <Telegram.exe>
       python patcher.py --patch   display|network|both  <Telegram.exe>
       python patcher.py --restore <Telegram.exe>
"""

import os, sys, re, struct, shutil, datetime, bisect, argparse

try:
    import pefile
except ImportError:
    pefile = None
try:
    import capstone
    _CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
except Exception:
    capstone = None
    _CS = None

TID_GETSPONSORED = 0x3D6CE850          # messages.getSponsoredMessages ctor id

# Display-gate entry signature. Wildcards: the peer struct offset, the two short
# jcc displacements, and the channel-flags offset. 0x2000 ads flag + shr/cmp 2.
DISPLAY_SIG = ("48 89 5C 24 10 4C 8B 81 ?? ?? ?? ?? 48 8B D1 4D 8B 48 08 "
               "49 8B C1 48 C1 E8 30 44 0F B6 D8 84 C0 75 ?? 4D 85 C0 74 ?? "
               "41 F7 80 ?? ?? ?? ?? 00 20 00 00")
# Same, as it looks AFTER patching (first 3 bytes replaced by 31 C0 C3).
DISPLAY_SIG_PATCHED = ("31 C0 C3 24 10 4C 8B 81 ?? ?? ?? ?? 48 8B D1 4D 8B 48 08 "
                       "49 8B C1 48 C1 E8 30 44 0F B6 D8 84 C0 75 ?? 4D 85 C0 74 ?? "
                       "41 F7 80 ?? ?? ?? ?? 00 20 00 00")
DISPLAY_PATCH = bytes([0x31, 0xC0, 0xC3])      # xor eax,eax ; ret
NOP5 = b"\x90" * 5


def sig_to_regex(sig):
    out = b""
    for tok in sig.split():
        out += b"." if tok == "??" else re.escape(bytes([int(tok, 16)]))
    return re.compile(out, re.DOTALL)


class PatchError(Exception):
    pass


class PEView:
    def __init__(self, path):
        if pefile is None:
            raise RuntimeError("pefile is required: pip install pefile")
        self.path = path
        with open(path, "rb") as f:
            self.raw = bytearray(f.read())
        self.pe = pefile.PE(path, fast_load=True)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = self.pe.sections
        self.text = next(s for s in self.sections
                         if s.Name.rstrip(b"\x00") == b".text")
        self.text_lo = self.text.PointerToRawData
        self.text_hi = self.text_lo + self.text.SizeOfRawData
        self.text_vrva = self.text.VirtualAddress
        self._pdata = None

    def close(self):
        try:
            self.pe.close()
        except Exception:
            pass

    def version(self):
        try:
            self.pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            vi = self.pe.VS_FIXEDFILEINFO[0]
            ms, ls = vi.FileVersionMS, vi.FileVersionLS
            return "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
        except Exception:
            return "unknown"

    def off_to_rva(self, off):
        for s in self.sections:
            a = s.PointerToRawData
            b = a + s.SizeOfRawData
            if a <= off < b:
                return s.VirtualAddress + (off - a)
        return None

    def rva_to_off(self, rva):
        for s in self.sections:
            a = s.VirtualAddress
            b = a + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if a <= rva < b:
                return s.PointerToRawData + (rva - a)
        return None

    def pdata_funcs(self):
        if self._pdata is None:
            pd = next((s for s in self.sections
                       if s.Name.rstrip(b"\x00") == b".pdata"), None)
            funcs = []
            if pd:
                data = self.raw[pd.PointerToRawData:
                                pd.PointerToRawData + pd.SizeOfRawData]
                for i in range(0, len(data) - 11, 12):
                    beg, end, _ = struct.unpack("<III", data[i:i + 12])
                    if beg or end:
                        funcs.append((beg, end))
                funcs.sort()
            self._pdata = (funcs, [f[0] for f in funcs])
        return self._pdata

    def enclosing_func(self, rva):
        funcs, starts = self.pdata_funcs()
        i = bisect.bisect_right(starts, rva) - 1
        if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
            return funcs[i]
        return None

    def text_bytes(self):
        return bytes(self.raw[self.text_lo:self.text_hi])


def _entry(view, off, patch, orig, info):
    rva = view.off_to_rva(off)
    return {"off": off, "patch": patch, "orig": orig,
            "rva": rva, "va": view.image_base + rva, "info": info}


# --------------------------------------------------------------------------
# DISPLAY gate
# --------------------------------------------------------------------------
def locate_display(view):
    raw = bytes(view.raw)
    hits = [m.start() for m in sig_to_regex(DISPLAY_SIG).finditer(raw)]
    if len(hits) > 1:
        raise PatchError("display-gate signature matched %d times (expected 1)"
                         % len(hits))
    if len(hits) == 1:
        off = hits[0]
        orig = bytes(view.raw[off:off + len(DISPLAY_PATCH)])
        e = _entry(view, off, DISPLAY_PATCH, orig, "display gate")
        return [e]
    ph = [m.start() for m in sig_to_regex(DISPLAY_SIG_PATCHED).finditer(raw)]
    if len(ph) == 1:
        e = _entry(view, ph[0], DISPLAY_PATCH, None, "display gate (already patched)")
        return [e]
    raise PatchError("display-gate signature not found "
                     "(unsupported / changed version)")


# --------------------------------------------------------------------------
# NETWORK source
# --------------------------------------------------------------------------
def _find_serializers(view):
    """getSponsoredMessages TL id -> small writer function(s) -> their callers."""
    tb = view.text_bytes()
    tvs, tlo = view.text_vrva, view.text_lo
    id_bytes = struct.pack("<I", TID_GETSPONSORED)
    id_offs = [tlo + m.start() for m in re.finditer(re.escape(id_bytes), tb)]
    if not id_offs:
        raise PatchError("getSponsoredMessages id 0x%08X not present"
                         % TID_GETSPONSORED)
    writers = set()
    for off in id_offs:
        rva = view.off_to_rva(off)
        fn = view.enclosing_func(rva) if rva is not None else None
        if fn and (fn[1] - fn[0]) < 0x400:          # small = the writer, not the
            writers.add(fn[0])                      # giant response dispatcher
    if not writers:
        raise PatchError("could not bound the request-writer function")
    serializers = set()
    for m in re.finditer(b"\xe8", tb):              # direct call to a writer
        i = m.start()
        if i + 5 > len(tb):
            continue
        rel = struct.unpack("<i", tb[i + 1:i + 5])[0]
        if tvs + i + 5 + rel in writers:
            fn = view.enclosing_func(tvs + i)
            if fn:
                serializers.add(fn)
    if not serializers:
        raise PatchError("no caller of the request-writer found")
    return sorted(serializers)


def _is_mov_edx_reg(ins):
    return (ins.mnemonic == "mov"
            and re.match(r"^edx, [a-z][a-z0-9]{1,3}$", ins.op_str) is not None)


def _is_mov_rcx(ins):
    return ins.mnemonic == "mov" and ins.op_str.startswith("rcx,")


def _find_enqueue_sites(view, srva, erva):
    """Inside a serializer, the enqueue is the direct `call` set up with the
    request id in EDX and the api instance in RCX. Returns list of
    (file_off, already_noped)."""
    if _CS is None:
        raise PatchError("capstone is required to locate the network patch")
    so = view.rva_to_off(srva)
    code = bytes(view.raw[so:view.rva_to_off(erva)])
    ins = list(_CS.disasm(code, view.image_base + srva))
    out = []
    for i in range(2, len(ins)):
        if _is_mov_rcx(ins[i - 1]) and _is_mov_edx_reg(ins[i - 2]):
            cur = ins[i]
            off = view.rva_to_off(cur.address - view.image_base)
            if cur.mnemonic == "call" and cur.bytes and cur.bytes[0] == 0xE8:
                out.append((off, False))
            elif cur.mnemonic == "nop" and bytes(view.raw[off:off + 5]) == NOP5:
                out.append((off, True))
    return out


def locate_network(view):
    serializers = _find_serializers(view)
    entries = []
    for (s, e) in serializers:
        for off, noped in _find_enqueue_sites(view, s, e):
            if noped:
                entries.append(_entry(view, off, NOP5, None,
                                      "network enqueue (already patched)"))
            else:
                orig = bytes(view.raw[off:off + 5])
                entries.append(_entry(view, off, NOP5, orig, "network enqueue"))
    if not entries:
        raise PatchError("could not locate the enqueue call in the serializer")
    if len(entries) > 4:
        raise PatchError("resolved %d enqueue candidates (too many); aborting"
                         % len(entries))
    return entries


LOCATORS = {"display": locate_display, "network": locate_network}


def disasm_bytes(code, va):
    if _CS is None:
        return "    (capstone not installed)"
    out = []
    for ins in _CS.disasm(bytes(code), va):
        out.append("    0x%x: %-16s %s %s" %
                   (ins.address, ins.bytes.hex(" "), ins.mnemonic, ins.op_str))
    return "\n".join(out) if out else "    (could not disassemble)"


# --------------------------------------------------------------------------
# apply / restore
# --------------------------------------------------------------------------
def make_backup(path, log):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = "%s.%s.bak" % (path, ts)
    shutil.copy2(path, bak)
    log("Backup created: %s" % bak)
    return bak


def apply_patches(path, which, log, do_backup=True):
    """Locate and apply each selected patch independently. A patch that cannot
    be resolved is reported and skipped; the others still apply."""
    view = PEView(path)
    log("Target : %s" % path)
    log("Version: %s" % view.version())
    log("ImageBase 0x%x" % view.image_base)

    located, failed = {}, {}
    for name in which:
        try:
            located[name] = LOCATORS[name](view)
        except PatchError as e:
            failed[name] = str(e)

    to_write = []
    for name in which:
        if name in failed:
            log("\n[%s] NOT RESOLVED: %s  (skipped)" % (name.upper(), failed[name]))
            continue
        for en in located[name]:
            log("\n[%s] %s @ file 0x%08x  RVA 0x%08x  VA 0x%x" %
                (name.upper(), en["info"], en["off"], en["rva"], en["va"]))
            if en["orig"] is None:
                log("  already patched, nothing to do.")
                continue
            ctx = bytes(view.raw[en["off"]:en["off"] + max(len(en["patch"]), 16)])
            log("  before: %s" % en["orig"].hex(" "))
            log(disasm_bytes(ctx, en["va"]))
            log("  after : %s" % en["patch"].hex(" "))
            log(disasm_bytes(en["patch"], en["va"]))
            to_write.append(en)

    if not located:
        log("\nNothing could be located; no changes written.")
        view.close()
        return False
    if not to_write:
        log("\nAll located patches are already applied. No changes written.")
        view.close()
        return len(failed) == 0

    if do_backup:
        make_backup(path, log)
    for en in to_write:
        view.raw[en["off"]:en["off"] + len(en["patch"])] = en["patch"]
    view.close()
    with open(path, "wb") as f:
        f.write(bytes(view.raw))
    log("\nWrote %d patch site(s)." % len(to_write))

    verify = PEView(path)
    allok = True
    for en in to_write:
        now = bytes(verify.raw[en["off"]:en["off"] + len(en["patch"])])
        good = now == en["patch"]
        allok = allok and good
        log("  verify @0x%08x: %s  %s" %
            (en["off"], now.hex(" "), "OK" if good else "MISMATCH"))
        log(disasm_bytes(now, en["va"]))
    verify.close()

    if failed:
        log("\nRESULT: applied [%s]; could NOT resolve [%s]." %
            (", ".join(n for n in which if n not in failed),
             ", ".join(failed)))
    else:
        log("\nRESULT: %s" % ("all selected patches verified OK" if allok
                              else "VERIFY FAILED"))
    return allok and not failed


def list_backups(path):
    d = os.path.dirname(os.path.abspath(path)) or "."
    base = os.path.basename(path)
    baks = [os.path.join(d, f) for f in os.listdir(d)
            if f.startswith(base + ".") and f.endswith(".bak")]
    baks.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return baks


def restore(path, log, bak=None):
    if bak is None:
        baks = list_backups(path)
        if not baks:
            log("No backup (*.bak) found next to %s" % path)
            return False
        bak = baks[0]
    shutil.copy2(bak, path)
    log("Restored %s\n     from %s" % (path, bak))
    return True


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("Telegram sponsored-message patcher")
    root.geometry("880x620")

    pathvar = tk.StringVar()
    for guess in (os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "work", "Telegram.exe"),
                  os.path.join(os.environ.get("APPDATA", ""),
                               "Telegram Desktop", "Telegram.exe")):
        if os.path.isfile(guess):
            pathvar.set(guess)
            break
    modevar = tk.StringVar(value="both")

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    ttk.Label(top, text="Telegram.exe:").grid(row=0, column=0, sticky="w")
    ttk.Entry(top, textvariable=pathvar, width=80).grid(row=0, column=1,
                                                        padx=6, sticky="we")

    def browse():
        p = filedialog.askopenfilename(
            title="Select Telegram.exe",
            filetypes=[("Telegram executable", "Telegram.exe"),
                       ("Executable", "*.exe"), ("All files", "*.*")])
        if p:
            pathvar.set(p)
    ttk.Button(top, text="Browse...", command=browse).grid(row=0, column=2)
    top.columnconfigure(1, weight=1)

    box = ttk.LabelFrame(root, text="What to patch", padding=10)
    box.pack(fill="x", padx=10)
    ttk.Radiobutton(box, variable=modevar, value="display",
                    text="Display gate only  - force the 'show sponsored?' check to false (safe, pure bool)").pack(anchor="w")
    ttk.Radiobutton(box, variable=modevar, value="network",
                    text="Network source only - never send the getSponsoredMessages request (no fetch)").pack(anchor="w")
    ttk.Radiobutton(box, variable=modevar, value="both",
                    text="Both  (recommended)").pack(anchor="w")

    logw = tk.Text(root, wrap="word", height=23,
                   font=("Consolas", 9) if sys.platform == "win32" else ("monospace", 9))
    logw.pack(fill="both", expand=True, padx=10, pady=10)

    def log(msg=""):
        logw.insert("end", str(msg) + "\n")
        logw.see("end")
        root.update_idletasks()

    def selected():
        m = modevar.get()
        return ["display", "network"] if m == "both" else [m]

    def do_locate():
        logw.delete("1.0", "end")
        p = pathvar.get()
        if not os.path.isfile(p):
            messagebox.showerror("Error", "File not found:\n%s" % p); return
        try:
            v = PEView(p)
            log("Version: %s   (%s)\n" % (v.version(), p))
            for name in selected():
                try:
                    for en in LOCATORS[name](v):
                        log("[%s] %s @ RVA 0x%08x" % (name.upper(), en["info"], en["rva"]))
                        if en["orig"] is not None:
                            log("    before %s  ->  after %s"
                                % (en["orig"].hex(" "), en["patch"].hex(" ")))
                except PatchError as e:
                    log("[%s] NOT RESOLVED: %s" % (name.upper(), e))
            v.close()
        except Exception as e:
            log("ERROR: %s" % e)

    def do_patch():
        logw.delete("1.0", "end")
        p = pathvar.get()
        if not os.path.isfile(p):
            messagebox.showerror("Error", "File not found:\n%s" % p); return
        installed = os.path.normcase(os.path.join(
            os.environ.get("APPDATA", ""), "Telegram Desktop", "Telegram.exe"))
        if os.path.normcase(os.path.abspath(p)) == installed:
            if not messagebox.askyesno(
                    "Patch installed copy?",
                    "This is your INSTALLED Telegram.exe.\n\nClose Telegram first. "
                    "Auto-update will later overwrite the patch, and the code "
                    "signature becomes invalid.\n\nA timestamped backup is made. "
                    "Continue?"):
                return
        try:
            ok = apply_patches(p, selected(), log, do_backup=True)
            messagebox.showinfo("Done", "Finished - see the log."
                                if ok else "Finished with skips - see the log.")
        except Exception as e:
            log("\nERROR: %s" % e)
            messagebox.showerror("Error", str(e))

    def do_restore():
        logw.delete("1.0", "end")
        p = pathvar.get()
        if not list_backups(p):
            messagebox.showwarning("No backup", "No *.bak file found next to the exe.")
            return
        bak = filedialog.askopenfilename(
            title="Choose a backup to restore",
            initialdir=os.path.dirname(os.path.abspath(p)),
            filetypes=[("Backup", "*.bak"), ("All files", "*.*")])
        if bak:
            try:
                restore(p, log, bak)
                messagebox.showinfo("Restored", "Original restored from backup.")
            except Exception as e:
                log("ERROR: %s" % e)

    btns = ttk.Frame(root, padding=(10, 0, 10, 10))
    btns.pack(fill="x")
    ttk.Button(btns, text="Locate / preview", command=do_locate).pack(side="left")
    ttk.Button(btns, text="Patch", command=do_patch).pack(side="left", padx=6)
    ttk.Button(btns, text="Restore from backup...", command=do_restore).pack(side="left")
    ttk.Label(btns, text="  Close Telegram before patching.").pack(side="left")

    log("Ready. 'Locate / preview' shows what would change without writing.")
    if not pathvar.get():
        log("Pick your Telegram.exe with Browse...")
    root.mainloop()


def main():
    ap = argparse.ArgumentParser(description="Telegram sponsored-message patcher")
    ap.add_argument("--locate", metavar="EXE")
    ap.add_argument("--patch", nargs=2, metavar=("MODE", "EXE"))
    ap.add_argument("--restore", metavar="EXE")
    args = ap.parse_args()

    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")

    def log(m=""):
        try:
            print(m)
        except Exception:
            pass

    if args.locate:
        v = PEView(args.locate)
        log("Version: %s" % v.version())
        for name in ("display", "network"):
            try:
                for en in LOCATORS[name](v):
                    log("[%s] %s @ file 0x%08x  RVA 0x%08x  VA 0x%x" %
                        (name.upper(), en["info"], en["off"], en["rva"], en["va"]))
                    if en["orig"] is not None:
                        log("  before %s / after %s" %
                            (en["orig"].hex(" "), en["patch"].hex(" ")))
                        log(disasm_bytes(bytes(v.raw[en["off"]:en["off"] + 16]), en["va"]))
                        log("  -->")
                        log(disasm_bytes(en["patch"], en["va"]))
            except PatchError as e:
                log("[%s] NOT RESOLVED: %s" % (name.upper(), e))
        v.close()
        return
    if args.patch:
        mode, exe = args.patch
        which = ["display", "network"] if mode == "both" else [mode]
        ok = apply_patches(exe, which, log, do_backup=True)
        sys.exit(0 if ok else 1)
    if args.restore:
        restore(args.restore, log)
        return
    run_gui()


if __name__ == "__main__":
    main()
