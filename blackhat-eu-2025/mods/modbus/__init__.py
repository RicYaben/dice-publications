from mods.modbus.fingerprint import modbus_fp_handler as fp_handler
from mods.modbus.classifier import modbus_cls_handler as cls_handler
from mods.modbus.classifier import modbus_cls_init as cls_init

from dice.module import Module
from mods.modbus.classifier import make_classifier
from mods.modbus.fingerprint import make_fingerprinter

# This is more clean, but not as useful. It makes it more difficult to test
# individual modules
# modules = build_modules(
#     name="modbus",
#     classifier=modbus_cls(),
#     fingerprinter=modbus_fp(),
# )

def make_modules() -> list[Module]:
    return [make_classifier(), make_fingerprinter()]

__all__ = [
    "fp_handler",
    "cls_handler",
    "cls_init",
    "make_modules",
]