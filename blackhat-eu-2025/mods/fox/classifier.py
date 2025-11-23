from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db
import pandas as pd

def fox_cls_init(mod: Module) -> None:
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticatied clients to communicate"
    )

def fox_cls_handler(mod: Module) -> None:
    repo = mod.repo()
    def handler(df: pd.DataFrame):
        labs = []
        for fp in df.itertuples(index=False):
            labs.append(mod.make_label(str(fp.id), "anonymous-connection"))
        repo.label(*labs)
    
    q = query_db("fingerprints", protocol="fox")
    mod.with_pbar(handler, q)

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "fox", fox_cls_handler, fox_cls_init)