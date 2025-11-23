import pandas as pd
import pytricia

class PrefixTree:
    """A fast prefix tree using PyTricia."""

    def __init__(self):
        # PyTricia tree for IPv4 and IPv6
        self.tree = pytricia.PyTricia(32)  # use 128 for IPv6 if needed

    def add(self, prefix: str, value):
        """Add a prefix with an associated value."""
        self.tree[prefix] = value

    def get(self, addr: str):
        """Return the value for the longest prefix match, or None if not found."""
        try:
            return self.tree.get(addr)
        except KeyError:
            return None

    def has(self, addr: str) -> bool:
        """Return True if the IP is within any known prefix."""
        return addr in self.tree

def build_prefix_tree(prefixes: list[str]) -> PrefixTree:
    tree = PrefixTree()
    for p in prefixes:
        tree.add(p, p)
    return tree

def build_resource_tree(flat: pd.DataFrame) -> PrefixTree:
    tree = PrefixTree()
    records = flat.to_dict("records")
    for rec in records:
        prefix = rec["prefix"]
        tree.add(prefix, rec)
    return tree

def flatten_resources(resources: pd.DataFrame) -> pd.DataFrame:
    # Remove prefix list column but keep other data
    meta_cols = resources.columns.drop("prefixes")

    # Explode rows so each prefix gets its own row
    flat = resources.explode("prefixes")

    # Rename prefix column
    flat = flat.rename(columns={"prefixes": "prefix"})
    return flat[["prefix"] + meta_cols.tolist()]