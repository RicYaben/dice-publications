from mods.fox.fingerprint import fox_fp_handler as fp_handler
from mods.fox.classifier import fox_cls_handler as cls_handler
from mods.fox.classifier import fox_cls_init as cls_init

from dice.module import Module
from mods.fox.classifier import make_classifier
from mods.fox.fingerprint import make_fingerprinter

def make_modules() -> list[Module]:
    return [make_classifier(), make_fingerprinter()]

__all__ = [
    "fp_handler",
    "cls_handler",
    "cls_init",
    "make_modules",
]