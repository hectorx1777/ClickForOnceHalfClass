"""
Ad-hoc string tag for export / module names — matches C# ApiHash.Hash.

Same uint32 wrap as C#: add / subtract / multiply on masked values.

Example:
  python hashbewerber.py functiuonname
  -> 0xFFFFAF45
"""
from __future__ import annotations

import sys


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def hash_name(s: str) -> int:
    n = len(s)
    u = u32(1009 - n)
    v = u32(n + 9176)
    for k in range(n):
        c = ord(s[k])
        u = u32(u + c - k)
        v = u32(v - c + k)
        v = u32(v + u - c)
    return u32(u - v + n * 503)


def main() -> None:
    args = sys.argv[1:]
    if not args:
        names = [
            "LdrCallEnclave",
            "ntdll.dll",
            "kernel32.dll",
            "user32.dll",
            "CreateProcessA",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "ResumeThread",
            "MessageBoxW",
            "LoadLibraryW",
            "CreateThreadpoolTimer",
            "gdi32.dll",
            "ole32.dll"
        ]
    else:
        names = args
    for name in names:
        h = hash_name(name)
        print(f"{name!r} -> 0x{h:08X} ({h})")


if __name__ == "__main__":
    main()
