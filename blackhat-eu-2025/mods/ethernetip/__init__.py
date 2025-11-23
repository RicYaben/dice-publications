from mods.ethernetip.classifier import ethernetip_cls_handler as cls_handler
from mods.ethernetip.classifier import ethernetip_cls_init as cls_init

from dice.module import Module
from mods.ethernetip.classifier import make_classifier
from mods.ethernetip.fingerprint import make_fingerprinter

def make_modules() -> list[Module]:
    return [make_classifier(), make_fingerprinter()]

__all__ = [
    "cls_handler",
    "cls_init",
    "make_modules",
]