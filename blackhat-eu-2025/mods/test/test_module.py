import dice

from dice import module
from dice import helpers
from dice import loaders

from mods.ethernetip import fingerprint as fp
from mods.ripe import scanner as sc
from mods.cti import scanner as cti

import os
import unittest
import pandas as pd

class TestModule(unittest.TestCase):
    def test_ethernetip_fp(self):
        data = "63003700000000000000000000000000000000000000000001000c00310001000002af12c0a80108000000000000000001000e00b4000c0b3400231e43d00f323038302d4c4332302d323051574203"

        vendors = pd.read_csv("data/EthernetIP/vendors.csv")
        devices = pd.read_csv("data/EthernetIP/devices.csv")

        ret = fp.parse_list_identity(data, vendors, devices)
        self.assertIsNotNone(ret)

    def test_ripe_sc(self):
        cmp_fp = dice.new_fingerprinter(sc.make_asn_scn_handler())
        engine = module.new_engine(cmp_fp)

        recs = [
            {"ip": "166.167.68.63", "port": 4242, "data": {"test": {"status": "success", "protocol": "test"}}},
            {"ip": "142.165.176.100", "port": 4242, "data": {"test": {"status": "success", "protocol": "test"}}}
        ]
        src = helpers.new_source("zgrab2", "-", "-", loader=loaders.with_records(recs))
        repo = engine.run([src])
        # run a query to get all the fingerprints from these joined with their ip
        res = repo.get_fingerprints("166.167.68.63", "142.165.176.100")
        self.assertIsNotNone(res)

    def test_cti_scanner(self):
        scanner = "shodan"
        api_key = os.environ.get(f"{scanner.upper()}_KEY", "")
        scn = cti.get_scanner(scanner)

        hosts = ["166.167.68.63", "142.165.176.100", "63.46.83.31"]
        res = scn(api_key, hosts)
        self.assertIsNot([], res)
