from dice.module import make_fp_handler, Module, new_module
from dice.helpers import get_record_field 
from dice.config import FINGERPRINTER
import pandas as pd

def fingerprint(row: pd.Series) -> dict | None:
    sdt = get_record_field(row, "startdt")
    tfr = get_record_field(row, "testfr")
    asdus = get_record_field(row, "interrogation", [])
    if (not pd.isna(asdus)) and (asdus):
        return dict(
            asdus=asdus,
            sdt=sdt is None,
            tfr=tfr is None
        )

iec104_fp_handler = make_fp_handler(fingerprint, "iec104")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "iec104", iec104_fp_handler)