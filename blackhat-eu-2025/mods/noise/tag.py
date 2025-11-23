from dice.module import ModuleHandler, Module, new_module
from dice.config import TAGGER
from typing import Callable

from mods.noise.condensation import tag_condensed, condensation_init
from mods.noise.volatility import tag_volatile, volatility_init
from mods.noise.hostility import hostility_init, tag_hostile
from mods.noise.displacement import tag_displaced, displacement_init

type NoiseTag = Callable[[Module], None]

def get_noise_tag(noise: str) -> NoiseTag:
    match noise:
        case "condensation":
            return tag_condensed
        case "displacement":
            return tag_displaced
        case "hostility":
            return tag_hostile
        case "volatility":
            return tag_volatile
        case _:
            raise Exception(f"unknown noise source: {noise}")

def make_noise_tag_handler(noise: str) -> ModuleHandler:
    handler = get_noise_tag(noise)
    return lambda mod: handler(mod)

def make_tags() -> list[Module]:
    return [
        new_module(TAGGER, "condensation", tag_condensed, condensation_init),
        new_module(TAGGER, "displacement", tag_displaced, displacement_init),
        new_module(TAGGER, "hostility", tag_hostile, hostility_init),
        new_module(TAGGER, "volatile", tag_volatile, volatility_init),
    ]