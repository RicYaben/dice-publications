import unittest

from dice import make_sources, new_engine
from dice.repo import save
from mods.registry import REGISTRY
from dice.module import new_component_manager, load_repository
import pandas as pd

class TestCommands(unittest.TestCase):
    def test_insert_zgrab2(self):
        repo = load_repository()

        srcs = make_sources("modules/test/data/zgrab2.jsonl", name="zgrab2", batch_size=10000)
        repo.add_sources(*srcs)

    def test_classify(self):
        srcs = make_sources("modules/test/data/*.jsonl", name="zgrab2", batch_size=10000)
        manager = new_component_manager("-").add(*REGISTRY.all())
        components = manager.build(modules=["ethernetip"])
        engine = new_engine(*components)

        repo = load_repository(srcs)
        con = repo.get_connection()

        vendors = pd.read_csv("modules/test/data/vendors.csv")
        devices = pd.read_csv("modules/test/data/devices.csv")
        save(con, "eip_vendors", vendors)
        save(con, "eip_devices", devices)

        engine.run(repo=repo)