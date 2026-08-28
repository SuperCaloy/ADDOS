"""Shared stub loader for offline topology imports (see
test_attacker_inventory._load_topology for the original pattern)."""
import importlib.util
import sys
import types


def load_topology_stubbed(module_name: str):
    mn = types.ModuleType("mininet")
    for sub in ("log", "net", "node", "cli", "link"):
        m = types.ModuleType(f"mininet.{sub}")
        if sub == "log":
            m.info = lambda *a, **k: None
            m.setLogLevel = lambda *a, **k: None
        elif sub == "net":
            m.Mininet = object
        elif sub == "node":
            m.RemoteController = object
            m.OVSKernelSwitch = object
        elif sub == "cli":
            m.CLI = object
        elif sub == "link":
            m.Link = object
        sys.modules.setdefault(f"mininet.{sub}", m)
        setattr(mn, sub, m)
    sys.modules.setdefault("mininet", mn)

    spec = importlib.util.spec_from_file_location(module_name, "topology/topology.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod
