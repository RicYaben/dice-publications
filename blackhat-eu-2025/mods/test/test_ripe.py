import ast
import unittest

from dice.module import load_repository
from dice.helpers import new_host

from mods.ripe.scanner import fetch_ris 
from mods.ripe.helpers import build_resource_tree

class TestRipe(unittest.TestCase):
    def test_fetch_ris(self):
        addr = "130.226.254.28"
        ris = fetch_ris(addr)
        self.assertIsNot(None, ris)

    def test_hosts(self):
        repo = load_repository(db="cosmos.db")
        q = """
        SELECT DISTINCT ip
        FROM records_zgrab2;
        """

        # I think I have to make a tree,
        # put the ASN info there, and then go addr by
        # addr fetching it
        resources = repo.get_records(normalize=True, source="resources")
        resources["prefixes"] = resources["prefixes"].apply(ast.literal_eval)
        tree = build_resource_tree(resources)

        batches = repo.query_batch(q)
        for b in batches:
            hosts = []
            addrs = b["ip"].tolist()
            for addr in addrs:
                info = tree.get(addr)
                assert isinstance(info, dict)

                host = new_host(addr, prefix=info["prefix"], asn=info["asn"])
                hosts.append(host)
            repo._add_items(*hosts, name="hosts")