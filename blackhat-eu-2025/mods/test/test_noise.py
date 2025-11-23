from dice.helpers import new_source
from dice.loaders import with_records
from dice.repo import load_repository
from dice.module import new_module

import unittest
import pandas as pd
from mods.noise.condensation import model_condensation
from mods.noise.displacement import aletheia_tag, displacement_init, model_host_ports

import random
import ipaddress

def generate_prefix_data(num_sizes=3, rows_per_prefix=5, almost_full_rows=2):
    """
    Generate test data for density model with automatically selected prefix sizes.
    
    Args:
        num_sizes (int): Number of different prefix sizes to generate (from /24 to /26).
        rows_per_prefix (int): Number of normal rows per prefix.
        almost_full_rows (int): Number of rows close to full capacity per prefix.
    
    Returns:
        list[dict]: List of dicts with "prefix" and "count".
    """
    data = []
    used_prefixes = set()
    possible_sizes = [24, 25, 26]

    # Randomly pick `num_sizes` distinct prefix sizes
    sizes = random.sample(possible_sizes, min(num_sizes, len(possible_sizes)))

    for size in sizes:
        # Decide how many prefixes of this size to generate (1 per size for simplicity)
        num_prefixes = 1

        while len(used_prefixes) < num_prefixes + len(used_prefixes):
            net_int1 = random.randint(0, 254)
            net_int2 = random.randint(0, 254)
            prefix = f"10.{net_int1}.{net_int2}.0/{size}"
            if prefix in used_prefixes:
                continue
            used_prefixes.add(prefix)

            capacity = ipaddress.ip_network(prefix).num_addresses

            # Normal rows
            for _ in range(rows_per_prefix):
                count = random.randint(1, max(1, capacity // 10))  # small occupancy
                data.append({"prefix": prefix, "count": count})

            # Almost full rows
            for _ in range(almost_full_rows):
                count = random.randint(int(0.85 * capacity), capacity)
                data.append({"prefix": prefix, "count": count})

    return data


class TestNoise(unittest.TestCase):
    def test_condensation(self):
        tdata = generate_prefix_data(
            num_sizes=3, 
            rows_per_prefix=10, 
            almost_full_rows=2
        )

        df = pd.DataFrame.from_records(tdata)
        model_condensation(df)

        dense = df[df["p_dense"] > .75]["prefix"].tolist()
        print(len(dense))

        self.assertIs(len(dense), 6)

    def test_displacement_ports(self):
        tdata = [
            {"ip": "ip1", "count": 2},
            {"ip": "ip1", "count": 2},
            {"ip": "ip1", "count": 1},
            {"ip": "ip1", "count": 3},
            {"ip": "ip1", "count": 5},
            {"ip": "ip1", "count": 10},
            {"ip": "ip1", "count": 3},
            {"ip": "ip1", "count": 2},
        ]

        model = model_host_ports(tdata)
        threshold =  model.percentile(75)
        high = list(filter(lambda x: x["count"] > threshold, tdata))
        
        self.assertIs(len(high), 2)

    def test_aletheia(self):
        recs = [
            {"saddr":"1.1.1.1", "sport":1,"dport":0,"window":6372,"tcpopt_wscale":64,"ttl":64},
            {"saddr":"2.2.2.2", "sport":1,"dport":0,"window":502,"tcpopt_wscale":256,"ttl":45},
            {"saddr":"3.3.3.3", "sport":1,"dport":0,"window":0,"ttl":64},
        ]

        src = new_source("zmap", "-", "-", loader=with_records(recs))
        r = load_repository([src])

        m = new_module("tag", "aletheia", lambda mod: aletheia_tag(mod), displacement_init)
        m.init(r)
        m.handle()

        res = r.get_tags("1.1.1.1", "2.2.2.2", "3.3.3.3")
        self.assertIsNotNone(res)