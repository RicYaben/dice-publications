from dice.models import Model
from dataclasses import dataclass

@dataclass
class AutonomousSystem(Model):
    id: str
    asn: str
    name: str
    contacts: list[str]

@dataclass
class Resource(Model):
    id: str
    # AS number
    asn: str
    # prefix resource
    resource: str
    # all the rest of resources in this location
    prefixes: list[str]
    country: str
    city: str
    latitude: str
    longitude: str