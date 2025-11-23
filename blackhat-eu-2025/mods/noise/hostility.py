import dice.query as dq

from dice.module import Module
from tdigest import TDigest

from mods.noise.factory import NoiseEvaluator, NoiseEvaluatorFactory

def is_timeout(fp) -> bool:
    return fp["status"] == "io-timeout" and fp["data"]

def iec_tarpit(mod: Module) -> NoiseEvaluator:
    'Calculate the distribution of IOAs and return when crosses the 95prc'

    # TODO: update this query. Get only those with
    # at least one ioa
    q = """
    SELECT ioas, COUNT(ioas) AS count
    FROM fingerprints
    WHERE protocol == "iec104";
    """
    digest = TDigest()
    for r in mod.repo().query(q):
        digest.update(r["count"])

    threshold = digest.percentile(95)
    def ev(fp) -> None:
        # If it timed out and the number of IOAs with type 36 (M_ME_TF_1), a measured value with timestamp
        # is very large, then flag this
        if len(fp["interrogation"]) > threshold:
            mod.tag_fp(fp, "tarpit", "too many IOAs")
    return ev

def modbus_tarpit(mod: Module) -> NoiseEvaluator:
    'Too many objects in the mei response'
    
    # TODO: at least one object and more follows
    q = """
    SELECT objects, COUNT(objects) AS count
    FROM fingerprints
    WHERE protocol == "modbus"
    AND more_follows == True;
    """

    digest = TDigest()
    for r in mod.repo().query(q):
        digest.update(r["count"])
    threshold = digest.percentile(95)
    # 5 is the minimum required objects in the
    # mei response
    MIN_REQUIRED = 5
    if threshold < MIN_REQUIRED: threshold = MIN_REQUIRED
    def ev(fp) -> None:
        if len(fp["objects"]) > threshold:
            mod.tag_fp(fp, "tarpit", "too many objects. More follows")
    return ev
        
def make_tarpit_factory(mod: Module) -> NoiseEvaluatorFactory:
    factory = NoiseEvaluatorFactory(mod)
    return factory.add("iec104", iec_tarpit).add("modbus", modbus_tarpit)

def tarpit_tag(mod: Module) -> None:
    factory = make_tarpit_factory(mod)
    # TODO: need to add status into the fps
    for p in factory.supported():
        ev = factory.get(p)
        if not ev:
            raise Exception(f"evaluator supported but not found: {p}")
        
        for fp in mod.query(dq.query_db("fingerprints", protocol=p)):
            ev(fp)

def tag_hostile(mod: Module) -> None: 
    'Test for tarpits and things sending us bad stuff'
    # NOTE: Malformed responses are handled by the probe.
    tarpit_tag(mod)
    # TODO: this one may be too difficult?
    # malware_tag(mod)

def hostility_init(mod: Module) -> None:
    mod.register_tag("tarpit", "Determines whether a service is a tarpot by picking lengthy connections with abnormally large amounts of data")