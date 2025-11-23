from mods.iec104.fingerprint import iec104_fp_handler as fp_handler
from mods.iec104.classifier import iec104_cls_handler as cls_handler
from mods.iec104.classifier import iec104_cls_init as cls_init

from dice.module import Module
from mods.iec104.classifier import make_classifier
from mods.iec104.fingerprint import make_fingerprinter

def make_modules() -> list[Module]:
    return [make_classifier(), make_fingerprinter()]

__all__ = [
    "fp_handler",
    "cls_handler",
    "cls_init",
    "make_modules",
]