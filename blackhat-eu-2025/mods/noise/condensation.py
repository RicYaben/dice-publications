from dice.module import Module
from dice.query import query_prefix_hosts, query_records
from dice.repo import save

from sklearn.linear_model import LinearRegression
from sklearn.mixture import GaussianMixture
from tqdm import tqdm

import ipaddress
import pandas as pd
import numpy as np

def describe_condensation(df: pd.DataFrame) -> pd.DataFrame:
    """
    Summarize condensation info grouped by prefix length (/n).
    Shows descriptive statistics for size, density, and p_dense.
    """
    grouped = []

    for slash, g in df.groupby("slash"):
        sizes = g["size"]
        densities = g["density"]
        p_dense = g["p_dense"]

        grouped.append({
            "slash": slash,
            "count_prefixes": len(g),

            # size stats
            "size_mean": sizes.mean(),
            "size_p50": sizes.median(),
            "size_p90": sizes.quantile(0.90),
            "size_p99": sizes.quantile(0.99),
            "size_min": sizes.min(),
            "size_max": sizes.max(),
            "size_total_hosts": sizes.sum(),

            # density stats
            "density_mean": densities.mean(),
            "density_p50": densities.median(),
            "density_p90": densities.quantile(0.90),

            # condensation (GMM probability)
            "p_dense_mean": p_dense.mean(),
            "p_dense_p90": p_dense.quantile(0.90),
        })

    summary = pd.DataFrame(grouped)
    return summary.sort_values("slash")

def model_condensation(df: pd.DataFrame) -> None:
    df["slash"] = df["prefix"].apply(lambda p: f"/{ipaddress.ip_network(p).prefixlen}")
    df["size"] = [2 ** (32 - ipaddress.ip_network(p).prefixlen) for p in df["prefix"]]
    df["density"] = df["count"] / df["size"]

    # --- Step 1: baseline regression (log–log)
    X = np.asarray(np.log10(df["size"])).reshape(-1, 1)
    y = np.asarray(np.log10(df["density"].clip(lower=1e-9)))
    base_model = LinearRegression().fit(X, y)
    df["expected_density"] = 10 ** base_model.predict(X)

    # --- Step 2: residuals
    df["log_excess"] = np.log10(df["density"].clip(lower=1e-9) / df["expected_density"])

    # --- Step 3: Gaussian mixture
    Xg = np.asarray(df["log_excess"]).reshape(-1, 1)
    gmm = GaussianMixture(n_components=2, random_state=0).fit(Xg)
    probs = gmm.predict_proba(Xg)

    dense_component = np.argmax(gmm.means_)
    df["p_dense"] = probs[:, dense_component]

def tag_condensed(mod: Module) -> None:
    "Uses a model to determine prefix density and condensation"
    repo = mod.repo()
    prefixes = repo.get_connection().execute(query_prefix_hosts()).df()
    model_condensation(prefixes)
    desc = describe_condensation(prefixes)
    save(repo.get_connection(), "condensation_summary", desc)

    # Filter rows instead of just prefixes
    dense_df = prefixes[prefixes["p_dense"] > 0.95]

    with tqdm(total=len(dense_df), desc="condensation") as pbar:
        for _, row in dense_df.iterrows():
            tags = []
            hosts = repo.query(query_records("hosts", prefix=row["prefix"]))
            for h in hosts:
                # row["p_dense"] is now available
                # TODO: Need to add the module
                tags.append(mod.make_tag(
                    h["ip"],
                    "dense",
                    details=f'probability: {row["p_dense"]:.3f}'
                ))
            mod.repo().tag(*tags)
            pbar.update(1)

def condensation_init(mod: Module) -> None:
    mod.register_tag("dense", "Condensation model to estimate whether a prefix is abnormally populated based on how dense other prefixes of similar size are")