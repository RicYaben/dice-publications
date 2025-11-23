from dice.module import make_fp_handler, Module, new_module
from dice.helpers import get_record_field, record_to_dict 
from dice.config import FINGERPRINTER

def fingerprint(row) -> dict | None:
    is_fox = get_record_field(row, "is_fox", False)
    version = get_record_field(row, "version")
    if is_fox and version:
        return record_to_dict(row)

fox_fp_handler = make_fp_handler(fingerprint, "fox")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "fox", fox_fp_handler)