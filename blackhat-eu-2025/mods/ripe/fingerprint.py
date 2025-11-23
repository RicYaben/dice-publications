from dice.module import Module, ModuleHandler
from mods.ripe.helpers import PrefixTree, build_resource_tree

from typing import Any

import pandas as pd

def fingerprint(mod: Module, row: pd.Series, tree: PrefixTree) -> Any:
    if (fp := tree.get(row["ip"])) is not None:
        mod.fingerprint(row, fp, "ripe")

def make_asn_fp_handler(resources: pd.DataFrame) -> ModuleHandler:
    tree = build_resource_tree(resources)
    def handler(mod: Module) -> None:
        recs = mod.repo().get_records(normalize=False, source="zgrab2")
        recs.apply(lambda r: fingerprint(mod, r, tree), axis=1)
    return handler