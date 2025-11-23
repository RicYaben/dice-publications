from dice.module import Module
from typing import Any, Generator
from difflib import ndiff

import pandas as pd
import numpy as np

def fmt_diff(*values: Any) -> str:
    """
    Returns a git-style diff of multiple values.
    If given two values, behaves like normal diff.
    If more than two, compares each consecutive pair.
    """
    if not values:
        return ""

    if len(values) == 1:
        # Only one value — just return it as string
        return str(values[0])

    diffs = []
    for i in range(len(values) - 1):
        old = str(values[i]).splitlines()
        new = str(values[i + 1]).splitlines()
        diff = '\n  '.join(ndiff(old, new))
        diffs.append(f"Diff {i} → {i+1}:\n  {diff}")

    return '\n'.join(diffs)

def is_equal(*vals: Any) -> bool:
    """Safely compare an arbitrary number of values, handling lists, arrays, and objects."""
    if len(vals) < 2:
        return True  # nothing to compare

    first = vals[0]

    for other in vals[1:]:
        # If either value is a list or ndarray, convert both to np.array and compare
        if isinstance(first, (list, np.ndarray)) or isinstance(other, (list, np.ndarray)):
            if not np.array_equal(np.asarray(first), np.asarray(other)):
                return False
        else:
            if first != other:
                return False
    return True

def eval_diff(df: pd.DataFrame) -> str | None:
    # we only care about the fps "data_*" fields
    cols = filter(lambda c: c.startswith("data_"), df.columns)
    difs = []
    for col in cols:
        vals = df[col].to_list()
        if not is_equal(*vals):
            d = fmt_diff(vals)
            difs.append(f"- {col.replace("data_", "")}:\n{d}")

    if difs:
        return "\n".join(difs)
        
def eval_intermitent(fps: list[Any]) -> str | None:
    'check if there is data, or if there is an error of not available (no data)'

    # io-timeout, connection-timeout, or unknown-error?
    avi = list(filter(lambda s: s["data"], fps))
    if len(avi) and len(avi) < len(fps):
        if avi[0] :
            return "became unavailable after the first scan"
        return "eventually became available"
    
def pull_next(rows) -> Generator[tuple[dict, list[Any]], None, None]:
    # we get rows order by ip,protocol,port
    summary = {"host": None,"protocol": None,"port": None}
    res = []
    for row in rows:
        curr = {
            "host": row["host"],
            "protocol": row["protocol"],
            "port": row["port"]
        }

        if (summary["host"] is not None) and (summary != curr):
            yield summary, res
            res = []

        summary = curr
        res.append(row)

    if res:
        yield summary, res

def mtd_tag(mod: Module) -> None:
    q = """
    SELECT f.*
    FROM fingerprints AS f
    ORDER BY f.host, f.protocol, f.port;
    """
    rows = mod.repo().query(q)
    for summary, fps in pull_next(rows):
        if idet := eval_intermitent(fps):
            mod.tag(summary["host"], "mtd-intermitent", idet, summary["protocol"], summary["port"])

        if d := eval_diff(pd.DataFrame.from_records(fps)):
            mod.tag(summary["host"], "mtd-different", d, summary["protocol"], summary["port"])

def tag_volatile(mod: Module) -> None: 
    'Requires multiple scans to compare results'
    mtd_tag(mod)


def volatility_init(mod: Module) -> None:
    mod.register_tag("mtd-intermitent", "Host appears and dissapear")
    mod.register_tag("mtd-different", "Host changed properties")