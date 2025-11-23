from dice.module import Module
from tdigest import TDigest

import dice.query as dq

from mods.noise.factory import NoiseEvaluator, NoiseEvaluatorFactory, NoiseHandlerFactory

def model_host_ports(ports) -> TDigest: 
    digest = TDigest()
    for r in ports:
        digest.update(r["count"])
    return digest

def default_ev_odd(_) -> None: return

def enip_odd(mod: Module) -> NoiseEvaluator:
    # TODO: this is only once to fix serials
    q_serial = """
        SELECT f.serial, COUNT(f.serial) AS count
        FROM fingerprints as f
        WHERE f.protocol == "enip"
            AND count > 1
        GROUP BY f.serial;
    """
    for fp in mod.query(q_serial):
        mod.tag_fp(fp, "odd", "reused serial")
    return default_ev_odd

def iec_odd(mod: Module) -> NoiseEvaluator:
    """
    Flags 2 behaviors:
    - contains type 100 for CAs 1,2, and 10 (the ones scan for normally)
    - same IOA responds multiple times with the same value
    """
    # TODO: this should be an argument. Others may scan differently
    scanned = [1,2,10,65535]
    f100 = lambda asdu: asdu["TypeID"] == 100 and asdu["CA"] in scanned
    f36 = lambda asdu: asdu["TypeID"] == 36

    def ev(fp) -> None:
        ioas = {}
        if asdus := fp.get("interrogation", []):
            if len(list(filter(f100, asdus))) >= int(len(scanned)*.75):
                mod.tag_fp(fp, "odd", "too many filled addresses")
                return

            for asdu in list(filter(f36, asdus)):
                for ioa in asdu.get("IOAs", []):
                    addr=ioa["Address"]
                    if addr not in ioas:
                        ioa[addr] = []
                    
                    v = ioa["Data"]
                    if v not in ioa[addr]:
                        ioa[addr].append(v)
                        continue

                    mod.tag_fp(fp, "odd", f'IOA responds multiple times with the same value+timestamp: {addr} "{v}"')
                    return
    return ev

def make_odd_service_factory(mod: Module) -> NoiseEvaluatorFactory:
    factory = NoiseEvaluatorFactory(mod)
    return factory \
        .add("enip", enip_odd) \
        .add("iec104", iec_odd)

def make_honeypot_factory(mod: Module) -> NoiseHandlerFactory:
    factory = NoiseHandlerFactory(mod)
    return factory \
        .add("cowrie", cowrie_hp) \
        .add("conpot", conpot_hp)

def aletheia_tag(mod: Module) -> None:
    '''hosting fingerprinting TCP window-based and scaling factor'''
    # ZMap records: window size and scaling factor
    q_not = dq.query_db("records_zmap",
        window__lte=0,
    )

    q_python = dq.query_db(
        "records_zmap",
        window__bt=[6370,6379],
        tcpopt_wscale=64,
    )

    q_cloud = dq.query_db(
        "records_zmap",
        window__bt=[502,509],
        tcpopt_wscale__bt=[128,256], 
    )

    q_cloud_2 = dq.query_db(
        "records_zmap",
        window__bt=[64_240,65_152],
        tcpopt_wscale__bt=[128,256], 
    )

    for q, d in [(q_not, "0 window"), (q_python, "python"), (q_cloud, "cloud"), (q_cloud_2, "cloud")]:
        hosts = mod.query(q)
        for h in hosts:
            mod.tag(h["saddr"], "aletheia", details=d, port=h["dport"])

def telescope_tag(mod: Module) -> None:
    'Telescopes do not host any service, but appear to have open ports to receive unsolicited traffic'
    repo = mod.repo()
    ports = repo.query(dq.query_zmap_ports())

    model = model_host_ports(ports)
    threshold =  model.percentile(75)
    for h in repo.query(dq.query_zmap_ports(count__gt=threshold)):
        mod.tag(h["ip"], "telescope")

def odd_tag(mod: Module) -> None:
    'Test for displacement, weird services'
    factory = make_odd_service_factory(mod)

    for p in factory.supported():
        ev = factory.get(p)
        if not ev:
            raise Exception(f"evaluator supported but not found: {p}")
        
        for fp in mod.query(dq.query_db("fingerprints", protocol=p)):
            ev(fp)

def honeypot_tag(mod: Module) -> None:
    factory = make_honeypot_factory(mod)
    for ev in factory.build_all():
        ev()

def tag_displaced(mod: Module) -> None:
    '''
    Simply compares protocol fingerprints and test for weird stuff:
    - many ports (uses a model to test how many ports are normal and correlations)
    - in cloud
    - aletheia
    - fingerprintable honeypots
    '''
    honeypot_tag(mod)
    aletheia_tag(mod)
    telescope_tag(mod)
    odd_tag(mod)

def displacement_init(mod: Module) -> None:
    mod.register_tag("aletheia", "OT fingerprinting method of A. Cordeiro et al.")
    mod.register_tag("telescope", "Gaussian distribution of the number of ports")
    mod.register_tag("honeypot", "Honeypot fingerprint")
    mod.register_tag("odd", "Tags suspicious properties, e.g., reused serial number")