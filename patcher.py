#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Desktop (Windows x64) sponsored-message patcher.

Two independent, signature / constant-anchored patches for channel sponsored
messages. Nothing is hardcoded to a fixed file offset; every location is found
dynamically and must resolve to exactly one site or the patch aborts.

  DISPLAY GATE  - Neutralizes the per-view "should this peer show sponsored
                  messages?" predicate so it always returns false. Patch:
                  the function entry becomes `xor eax,eax ; ret` (31 C0 C3).
                  Pure boolean, no side effects. Found by a wildcarded byte
                  signature (relocatable struct offsets wildcarded).

  NETWORK SOURCE- Stops the client from ever sending the
                  `messages.getSponsoredMessages` request, so channel
                  sponsored messages are never even fetched. The MTProto
                  enqueue call inside the request serializer is replaced with
                  NOPs; the serializer still runs its own epilogue and frees
                  the moved callback objects, so there is no leak. Located by
                  following the stable TL constructor id 0x3D6CE850 -> its
                  writer function -> the writer's unique caller (serializer)
                  -> the enqueue call.

Requires: Python 3, pefile.  (capstone optional, used only to pretty-print the
patched instructions for verification.)

GUI:   python patcher.py
CLI:   python patcher.py --locate <Telegram.exe>
       python patcher.py --patch display|network|both <Telegram.exe>
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

TID_GETSPONSORED = 0x3D6CE850  # messages.getSponsoredMessages constructor id (v7.x)

# --- DISPLAY GATE signature -------------------------------------------------
# Entry of the sponsored-eligibility predicate. Wildcards: the History/peer
# struct offset (mov r8,[rcx+disp32]), two short jcc rel8 displacements, and the
# channel-flags struct offset (test dword[r8+disp32], 0x2000). The 0x2000 ads
# flag mask and the shr/movzx/test idiom pin it down. Patched at match start.
DISPLAY_SIG = ("48 89 5C 24 10 4C 8B 81 ?? ?? ?? ?? 48 8B D1 4D 8B 48 08 "
               "49 8B C1 48 C1 E8 30 44 0F B6 D8 84 C0 75 ?? 4D 85 C0 74 ?? "
               "41 F7 80 ?? ?? ?? ?? 00 20 00 00")
DISPLAY_PATCH = bytes([0x31, 0xC0, 0xC3])            # xor eax,eax ; ret

# --- NETWORK enqueue micro-pattern (resolved *within* the serializer) -------
# mov rcx,[rdi+0x10] ; <call rel32 = MTProto enqueue>.  Generic on its own, so
# we only trust it inside the serializer function we reached via the TL id.
ENQUEUE_PRE = bytes([0x48, 0x8B, 0x4F, 0x10])
NOP5 = b"\x90" * 5


def sig_to_regex(sig):
    out = b""
    for tok in sig.split():
        out += b"." if tok == "??" else re.escape(bytes([int(tok, 16)]))
    return re.compile(out, re.DOTALL)


class PEView:
    """Thin helper over the raw file bytes with RVA<->offset mapping."""
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
        self._pdata = None

    def close(self):
        # pefile mmaps the file on Windows, which locks it; release before writing.
        try:
            self.pe.close()
        except Exception:
            pass

    def version(self):
        try:
            self.pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for fi in getattr(self.pe, "FileInfo", []):
                for entry in fi:
                    if getattr(entry, "Key", b"") == b"StringFileInfo":
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                if k in (b"FileVersion", b"ProductVersion"):
                                    return v.decode(errors="replace")
        except Exception:
            pass
        # fallback: fixed version info
        try:
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
        if self._pdata is not None:
            return self._pdata
        pd_sec = next((s for s in self.sections
                       if s.Name.rstrip(b"\x00") == b".pdata"), None)
        funcs = []
        if pd_sec:
            a = pd_sec.PointerToRawData
            data = self.raw[a:a + pd_sec.SizeOfRawData]
            for i in range(0, len(data) - 11, 12):
                beg, end, _unw = struct.unpack("<III", data[i:i + 12])
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


# --------------------------------------------------------------------------
# Locators. Each returns (file_offset, patch_bytes, orig_bytes, info) or raises.
# --------------------------------------------------------------------------
class PatchError(Exception):
    pass


def locate_display(view):
    rx = sig_to_regex(DISPLAY_SIG)
    hits = [m.start() for m in rx.finditer(bytes(view.raw))]
    if len(hits) == 0:
        # maybe already patched: 31 C0 C3 then the tail of the signature
        patched_sig = "31 C0 C3 24 10 4C 8B 81 ?? ?? ?? ?? 48 8B D1 4D 8B 48 08 49 8B C1 48 C1 E8 30"
        ph = [m.start() for m in sig_to_regex(patched_sig).finditer(bytes(view.raw))]
        if len(ph) == 1:
            return (ph[0], DISPLAY_PATCH, None,
                    "display gate ALREADY patched @0x%08x" % ph[0])
        raise PatchError("display-gate signature not found "
                         "(binary may be a different version)")
    if len(hits) > 1:
        raise PatchError("display-gate signature matched %d times (expected 1); "
                         "aborting" % len(hits))
    off = hits[0]
    orig = bytes(view.raw[off:off + len(DISPLAY_PATCH)])
    rva = view.off_to_rva(off)
    info = "display gate @ file 0x%08x  RVA 0x%08x  VA 0x%x" % (
        off, rva, view.image_base + rva)
    return (off, DISPLAY_PATCH, orig, info)


def locate_network(view):
    tid = struct.pack("<I", TID_GETSPONSORED)        # 50 e8 6c 3d
    tb = bytes(view.raw[view.text_lo:view.text_hi])
    # 1) occurrences of the constructor id inside .text
    id_offs = [view.text_lo + m.start() for m in re.finditer(re.escape(tid), tb)]
    if not id_offs:
        raise PatchError("getSponsoredMessages id 0x%08X not found" % TID_GETSPONSORED)
    # 2) small enclosing functions = writer candidates
    writer_rvas = set()
    for off in id_offs:
        rva = view.off_to_rva(off)
        fn = view.enclosing_func(rva) if rva is not None else None
        if fn and (fn[1] - fn[0]) < 0x400:
            writer_rvas.add(fn[0])
    if not writer_rvas:
        raise PatchError("could not bound the request-writer function")
    # 3) for each writer, find direct callers (e8 rel32 -> writer start)
    serializers = []
    for wrva in writer_rvas:
        for m in re.finditer(b"\xe8", tb):
            i = m.start()
            if i + 5 > len(tb):
                continue
            rel = struct.unpack("<i", tb[i + 1:i + 5])[0]
            call_rva = view.text.VirtualAddress + i
            if call_rva + 5 + rel == wrva:
                ser = view.enclosing_func(call_rva)
                if ser:
                    serializers.append(ser)
    serializers = sorted(set(serializers))
    if not serializers:
        raise PatchError("no caller of the request-writer found")
    # 4) inside each serializer, find the enqueue call: 48 8B 4F 10  E8 rel32
    targets = []
    for (srva, erva) in serializers:
        so = view.rva_to_off(srva)
        eo = view.rva_to_off(erva)
        body = bytes(view.raw[so:eo])
        for m in re.finditer(re.escape(ENQUEUE_PRE) + b"\xe8", body):
            call_off = so + m.start() + len(ENQUEUE_PRE)
            targets.append(call_off)
        # also detect the already-NOPed form
        for m in re.finditer(re.escape(ENQUEUE_PRE) + NOP5, body):
            call_off = so + m.start() + len(ENQUEUE_PRE)
            targets.append(("nop", call_off))
    plain = [t for t in targets if not isinstance(t, tuple)]
    noped = [t[1] for t in targets if isinstance(t, tuple)]
    if not plain and len(noped) == 1:
        return (noped[0], NOP5, None,
                "network source ALREADY patched @0x%08x" % noped[0])
    if len(plain) != 1:
        raise PatchError("network enqueue site resolved to %d candidates "
                         "(expected 1); aborting" % len(plain))
    off = plain[0]
    orig = bytes(view.raw[off:off + 5])
    rva = view.off_to_rva(off)
    info = "network enqueue @ file 0x%08x  RVA 0x%08x  VA 0x%x" % (
        off, rva, view.image_base + rva)
    return (off, NOP5, orig, info)


LOCATORS = {"display": locate_display, "network": locate_network}


def disasm_bytes(code, va):
    if _CS is None:
        return "  (capstone not installed; raw bytes only)"
    out = []
    for ins in _CS.disasm(bytes(code), va):
        out.append("    0x%x: %-14s %s %s" % (
            ins.address, ins.bytes.hex(" "), ins.mnemonic, ins.op_str))
    return "\n".join(out) if out else "  (could not disassemble)"


# --------------------------------------------------------------------------
# Apply / restore
# --------------------------------------------------------------------------
def make_backup(path, log):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = "%s.%s.bak" % (path, ts)
    shutil.copy2(path, bak)
    log("Backup created: %s" % bak)
    return bak


def apply_patches(path, which, log, do_backup=True):
    """which: list subset of ['display','network']. Returns True on success."""
    view = PEView(path)
    log("Target : %s" % path)
    log("Version: %s" % view.version())
    log("ImageBase 0x%x  .text file[0x%x..0x%x]" %
        (view.image_base, view.text_lo, view.text_hi))

    # locate everything first; abort entirely if any selected patch can't resolve
    plans = []
    for name in which:
        off, patch, orig, info = LOCATORS[name](view)
        log("\n[%s] %s" % (name.upper(), info))
        rva = view.off_to_rva(off)
        va = view.image_base + rva
        if orig is None:
            log("  -> already patched, nothing to do.")
            continue
        ctx = bytes(view.raw[off:off + max(len(patch), 16)])
        log("  before: %s" % orig.hex(" "))
        log(disasm_bytes(ctx, va))
        log("  after : %s" % patch.hex(" "))
        log(disasm_bytes(patch, va))
        plans.append((name, off, patch, orig, va))

    if not plans:
        log("\nAll selected patches are already applied. No changes made.")
        return True

    if do_backup:
        make_backup(path, log)

    for name, off, patch, orig, va in plans:
        view.raw[off:off + len(patch)] = patch
    view.close()                     # release mmap/lock before writing
    with open(path, "wb") as f:
        f.write(bytes(view.raw))
    log("\nWrote %d patch(es) to %s" % (len(plans), path))

    # verify by re-reading and disassembling
    verify = PEView(path)
    ok = True
    for name, off, patch, orig, va in plans:
        now = bytes(verify.raw[off:off + len(patch)])
        good = now == patch
        ok = ok and good
        log("  verify [%s] @0x%08x: %s  %s" %
            (name, off, now.hex(" "), "OK" if good else "MISMATCH"))
        log(disasm_bytes(now, va))
    verify.close()
    log("\nRESULT: %s" % ("all patches verified OK" if ok else "VERIFY FAILED"))
    return ok


def list_backups(path):
    d = os.path.dirname(os.path.abspath(path))
    base = os.path.basename(path)
    baks = [os.path.join(d, f) for f in os.listdir(d or ".")
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
    root.geometry("860x600")

    pathvar = tk.StringVar()
    # sensible default: working copy, else installed copy
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
    entry = ttk.Entry(top, textvariable=pathvar, width=78)
    entry.grid(row=0, column=1, padx=6, sticky="we")

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
                    text="Display gate only  - force the 'show sponsored?' check to false (safe, pure bool)"
                    ).pack(anchor="w")
    ttk.Radiobutton(box, variable=modevar, value="network",
                    text="Network source only - never send the getSponsoredMessages request (no fetch)"
                    ).pack(anchor="w")
    ttk.Radiobutton(box, variable=modevar, value="both",
                    text="Both  (recommended)").pack(anchor="w")

    logw = tk.Text(root, wrap="word", height=22,
                   font=("Consolas", 9) if sys.platform == "win32" else ("monospace", 9))
    logw.pack(fill="both", expand=True, padx=10, pady=10)

    def log(msg=""):
        logw.insert("end", msg + "\n")
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
            log("Version: %s   (%s)" % (v.version(), p))
            for name in selected():
                try:
                    off, patch, orig, info = LOCATORS[name](v)
                    log("[%s] %s" % (name.upper(), info))
                    if orig is not None:
                        log("   before %s  ->  after %s"
                            % (orig.hex(" "), patch.hex(" ")))
                except PatchError as e:
                    log("[%s] NOT RESOLVED: %s" % (name.upper(), e))
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
                    "This is your INSTALLED Telegram.exe.\n\n"
                    "Telegram must be closed, auto-update will later overwrite "
                    "the patch, and the Authenticode signature becomes invalid.\n\n"
                    "A timestamped backup will be made. Continue?"):
                return
        try:
            apply_patches(p, selected(), log, do_backup=True)
            messagebox.showinfo("Done", "Patching finished - see the log.")
        except Exception as e:
            log("\nABORTED: %s" % e)
            messagebox.showerror("Aborted", str(e))

    def do_restore():
        logw.delete("1.0", "end")
        p = pathvar.get()
        baks = list_backups(p)
        if not baks:
            messagebox.showwarning("No backup", "No *.bak file found next to the exe.")
            return
        bak = filedialog.askopenfilename(
            title="Choose a backup to restore",
            initialdir=os.path.dirname(os.path.abspath(p)),
            filetypes=[("Backup", "*.bak"), ("All files", "*.*")])
        if not bak:
            return
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
    ap.add_argument("--locate", metavar="EXE", help="resolve patch sites, no writes")
    ap.add_argument("--patch", nargs=2, metavar=("MODE", "EXE"),
                    help="MODE = display | network | both")
    ap.add_argument("--restore", metavar="EXE", help="restore newest .bak")
    args = ap.parse_args()

    # In a --windowed (no-console) build there is no stdout/stderr; keep prints
    # from crashing the CLI modes.
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
                off, patch, orig, info = LOCATORS[name](v)
                log("[%s] %s" % (name.upper(), info))
                if orig is not None:
                    va = v.image_base + v.off_to_rva(off)
                    ctx = bytes(v.raw[off:off + max(len(patch), 16)])
                    log("  before %s / after %s" % (orig.hex(" "), patch.hex(" ")))
                    log(disasm_bytes(ctx, va))
                    log("  -->")
                    log(disasm_bytes(patch, va))
            except PatchError as e:
                log("[%s] NOT RESOLVED: %s" % (name.upper(), e))
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
