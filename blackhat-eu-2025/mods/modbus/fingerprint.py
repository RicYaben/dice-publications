from dice.module import make_fp_handler, Module, new_module
from dice.helpers import get_record_field 
from dice.config import FINGERPRINTER
import pandas as pd
import numpy as np

def get_object(objs: list[dict], key):
    for k, v in objs:
        if k==key: return str(v).strip() if v else None

def fingerprint(row: pd.Series) -> dict | None:
    mei = get_record_field(row, "mei_response", {})
    if not mei or mei is np.nan:
        return
    
    objects = mei.pop("objects", {})
    ret = {
        **mei, 
        **objects,
        "unit_id": get_record_field(row, "unit_id", 0)
    }
    return ret

modbus_fp_handler = make_fp_handler(fingerprint, "modbus")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "modbus", modbus_fp_handler)