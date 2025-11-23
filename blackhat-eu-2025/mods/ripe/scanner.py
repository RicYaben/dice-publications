from uuid import uuid4
from dice.module import Module, ModuleHandler, Repository, new_module
from dice.models import Source, Host
from dice.helpers import new_source, new_host, with_model
from dice.loaders import with_records
from dice.query import query_db, query_records
from dice.config import SCANNER
from tqdm import tqdm
import ujson

from mods.ripe.models import AutonomousSystem, Resource
from mods.ripe.query import query_prefixes
from mods.ripe.fingerprint import make_asn_fp_handler
from mods.ripe.helpers import build_prefix_tree, build_resource_tree, flatten_resources

import pandas as pd

import ipaddress
import requests
import ast

API = "https://stat.ripe.net/data"
ENDPOINTS = {
    "ris": "network-info/data.json",
    "contact": "abuse-contact-finder/data.json",
    "name": "as-names/data.json",
    "prefixes": "maxmind-geo-lite-announced-by-as/data.json",
}

def get_ris(addr: str) -> dict | None:
    p = {"resource": addr}
    try:
        data = requests.get("/".join([API, ENDPOINTS["ris"]]), params=p).json()
        return data["data"]
    except Exception as e:
        print(f"failed to fetch ip {addr} info: {e}")

def fetch_ris(addr: str) -> dict | None:
    'returns basic AS info from an address'
    if net_info := get_ris(addr):
        return {"prefix": net_info.get("prefix", None), "asn": asn[0] if (asn := net_info.get("asns", [None])) else None}

def get_asn_name(asn: str) -> str:
    p = {"resource": asn}
    try:
        res = requests.get("/".join([API, ENDPOINTS["name"]]), params=p).json()
        return res["data"]["names"][asn]
    except Exception as e:
        print(f"failed to get ans info: {e}")
        return ""

def get_asn_contacts(asn: str) -> list[str]:
    p = {"resource": asn}
    try:
        res = requests.get("/".join([API, ENDPOINTS["contact"]]), params=p).json()
        return res["data"].get("abuse_contacts", [])
    except Exception as e:
        print(f"failed to get abuse contacts: {e}")
        return []

def get_asn_resources(asn: str) -> list[Resource]:
    p = {"data_overload_limit": "ignore", "resource": asn}
    try:
        res = requests.get("/".join([API, ENDPOINTS["prefixes"]]), params=p).json()
    except Exception as e:
        print(f"failed to get resources ({asn}): {e}")
        return []
    
    resources = []
    for pf in res["data"].get("located_resources"):
        res = pf.get("resource")
        if isinstance(ipaddress.ip_network(res), ipaddress.IPv6Network):
            continue # dont care about IPv6

        res = [make_resource(asn, res, loc) for loc in pf.get("locations")]
        resources.extend(res)
    return resources

def new_resource(asn: str, resource: str, prefixes: list[str], city: str, country: str, longitude: str, latitude: str) -> Resource:
    return Resource(str(uuid4()), asn, resource, prefixes, country, city, latitude, longitude)
    
def make_resource(asn: str, resource: str, loc: dict) -> Resource:
    return new_resource(
        asn, resource,
        prefixes=loc.get("resources", []),
        city=loc.get("city", ""),
        country=loc.get("country", ""),
        longitude=loc.get("longitude", ""),
        latitude=loc.get("latitude", ""),
    )

def new_asn(num: str, name: str, contacts: list[str]) -> AutonomousSystem:
    return AutonomousSystem(str(uuid4()), num, name, contacts)

def make_asn(asn: str) -> AutonomousSystem:
    return new_asn(
        asn, 
        name=get_asn_name(asn),
        contacts=get_asn_contacts(asn),
    )

def fetch_prefixes(repo: Repository, *addrs: str) -> Source:
    tree = build_prefix_tree(query_prefixes(repo))
    recs = []
    for addr in addrs:
        if tree.has(addr):
            continue
        ris = fetch_ris(addr)
        if ris and (px := ris.get("prefix")):
            tree.add(px, px)
            recs.append(ris)
    
    src = new_source("prefixes", "-", "-", loader=with_records(recs))
    return src

def fetch_asn(*asn: str) -> list[Source]:
    asns = []
    resources = []
    for n in asn:
        as_model = make_asn(n)
        asns.append(as_model.to_dict())
        res = get_asn_resources(n)
        resources.extend(res)

    asn_src = new_source("asn", "-","-", loader=with_records(asns))

    res = [r.to_dict() for r in resources]
    res_src = new_source("resources", "-","-", loader=with_records(res))
    return [asn_src, res_src]

# TODO: this is no-bueno
def make_asn_scn_handler() -> ModuleHandler:
    def handler(mod: Module) -> None:
        hosts = pd.DataFrame(mod.query(query_db("hosts")))

        # pre-fetch prefixes and their asn
        repo = mod.repo()
        pf_src = fetch_prefixes(repo, hosts["ip"].unique().tolist())

        # fetch ASNs info and add it to the db
        asns = []
        for df in pf_src.load():
            asns.extend(df["asn"].tolist())
        asn_src, res_src = fetch_asn(*set(asns))
        repo.add_sources(asn_src, res_src)

        # finally, send to fingerprint?
        resources = pd.concat(res_src.load())
        resources["prefixes"] = resources["prefixes"].apply(ast.literal_eval)
        h = make_asn_fp_handler(resources)
        h(mod)
    return handler

# TODO: this should be a generator so we dont explode memory
def scan(mod: Module) -> list[Source]:
    hosts = mod.query(query_records("hosts"))
    addrs = set([h["ip"] for h in hosts])
    prefixes = fetch_prefixes(mod.repo(), *addrs)

    # fetch ASNs info and add it to the db
    asns = []
    for df in prefixes.load():
        asns.extend(df["asn"].tolist())
    return fetch_asn(*set(asns))

def make_asn_scn() -> ModuleHandler:
    def handler(mod: Module) -> None:
        srcs = scan(mod)
        mod.repo().add_sources(*srcs)
    return handler

def make_scanner() -> Module:
    return new_module(SCANNER, "ripe", make_asn_scn())

def scan_hosts(mod: Module) -> None:
    repo = mod.repo()

    print("fetching records: ASN resources")
    resources = repo.get_records(normalize=True, source="resources")
    resources["prefixes"] = resources["prefixes"].apply(ujson.loads)

    print("flattening resource prefixes")
    flat = flatten_resources(resources)

    print("building resource tree")
    tree = build_resource_tree(flat)

    print("adding hosts")
    q = """
    SELECT DISTINCT ip
    FROM records_zgrab2
    """
    t, gen = repo.queryb(q, normalize=False)
    hosts: list[Host] = []
    with tqdm(total=t, desc="hosts") as pbar:
        for b in gen:
            for addr in b["ip"].tolist():
                info = tree.get(addr)
                if info:
                    host: Host = new_host(addr, prefix=info["prefix"], asn=info["asn"])
                    hosts.append(host)
            pbar.update(len(b.index))
    src = new_source("hosts", "-", "-", loader=with_model(hosts))
    mod.repo().add_source(src)

def make_hosts_scn() -> ModuleHandler:
    def handler(mod: Module) -> None:
         scan_hosts(mod)
    return handler

def make_hosts_scanner() -> Module:
    return new_module(SCANNER, "hosts", make_hosts_scn())