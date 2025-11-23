from dice.module import new_registry

# protocol cls and fps
from mods.ethernetip import make_modules as eip_m
from mods.modbus import make_modules as modbus_m
from mods.iec104 import make_modules as iec_m
from mods.fox import make_modules as fox_m
# noise tags
from mods.noise.tag import make_tags
# cti scanners
from mods.ripe.scanner import make_scanner as ripe_s
from mods.ripe.scanner import make_hosts_scanner as hosts_s
from mods.cti.scanner import make_scanners as cti_s

REGISTRY = new_registry("imc-2026").add(
    *modbus_m(),
    *fox_m(),
    *iec_m(),
    *eip_m(),
    *make_tags(),
    ripe_s(),
    hosts_s(),
    *cti_s(),
)