"""Exercise the real C ABI and socket lifecycle without contacting Telegram."""
import argparse
import ctypes
from pathlib import Path
import socket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    args = parser.parse_args()
    lib = ctypes.CDLL(str(args.library.resolve()))
    lib.StartProxy.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.SetCfProxyConfig.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    lib.GetStats.restype = ctypes.c_void_p
    lib.FreeString.argtypes = [ctypes.c_void_p]
    lib.SetPoolSize(0)
    lib.SetCfProxyConfig(0, 0, b"")
    secret = b"0123456789abcdef0123456789abcdef"
    assert lib.StartProxy(b"127.0.0.1", 65536, b"", secret, 0) == -2
    assert lib.StartProxy(b"127.0.0.1", 1443, b"", b"invalid", 0) == -2
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    for _ in range(5):
        assert lib.StartProxy(b"127.0.0.1", port, b"", secret, 0) == 0
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            assert lib.StopProxy() == 0
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
        ptr = lib.GetStats()
        try:
            assert "active=0 " in ctypes.string_at(ptr).decode()
        finally:
            lib.FreeString(ptr)
    print("Native ABI smoke: invalid inputs, 5 start/stop/rebind cycles and stats passed")


if __name__ == "__main__":
    main()
