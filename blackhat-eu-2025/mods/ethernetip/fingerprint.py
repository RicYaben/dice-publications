from dice.module import Module, ModuleHandler, new_module
from dice.helpers import get_record_field 
from dice.query import query_records
from dice.config import FINGERPRINTER

import base64
import struct
import pandas as pd

def is_vendor_obsolete(data):
    return data[["DNet", "CNet", "ENet"]].lt(0).all()

# vendors: https://marketplace.odva.org/vid.dat
# if the number is negative, we should return a "deprecated" state
def get_vendor_network_status(vendors: pd.DataFrame, vendor_id: int) -> tuple[str, str]:
    r = vendors[vendors["vendor_id"] == vendor_id]
    if not len(r):
        return (f"Unknown ({vendor_id})", "unknown")
    
    vrow = r.iloc[0]
    vname = vrow["Vendor Name"]

    if vrow["Vendor Name"] == "Reserved":
        return (vname, "reserved")
    
    if vrow["ENet"] > 0:
        return (vname,"active")
    
    if is_vendor_obsolete(vrow):
        return (vname, "obsolete")
    return (vname, "inactive")

# devices: https://marketplace.odva.org/technologies/1-ethernet-ip/products#?vendors=all&productTypes=all&deviceTypes=all&docYears=all&categories=all&services=none&page=1&lang=en&view=search&productDisplay=all
def get_device(devices: pd.DataFrame, device_id: int) -> str:
    d = devices[devices["device_id"] == device_id]
    if not len(d):
        return f"Unknown ({device_id})"
    return d.iloc[0]["Name"]

STATUS_FLAGS = {
    0x0001: "Owned",
    0x0002: "Configured",
    0x0004: "Minor Recoverable Fault",
    0x0008: "Minor Unrecoverable Fault",
    0x0010: "Major Recoverable Fault",
    0x0020: "Major Unrecoverable Fault",
    0x0040: "Extended Status Available",
}

def decode_status(status: int) -> list[str]:
    """Decode the Identity Object status bitfield into human-readable flags."""
    return [name for mask, name in STATUS_FLAGS.items() if status & mask]

def parse_encapsulation_header(data: bytes) -> dict:
    """
    Parse EtherNet/IP encapsulation header (24 bytes).
    """
    if len(data) < 24:
        raise ValueError("Packet too short for Encapsulation header")

    command, length, session, status = struct.unpack_from("<HHII", data, 0)
    sender_context = data[12:20]
    options, = struct.unpack_from("<I", data, 20)

    return {
        "command": command,
        "length": length,
        "session": session,
        "status": status,
        "sender_context": sender_context,
        "options": options,
        "payload": data[24:],  # return remaining data for further parsing
    }

def get_product_details(vendor: str, product: str) -> tuple[str,str,str]:
    """
    Returns the series of the product, the name of the product, and the version when possible
    """
    return (product, product, "")


def parse_list_identity_item(item_data: bytes, vendors: pd.DataFrame, devices: pd.DataFrame) -> dict:
    """
    Parse a single ListIdentity Item (Identity object).
    """

    protocol_version, = struct.unpack_from("<H", item_data, 0)
    _, sin_port = struct.unpack_from("!HH", item_data, 2)
    ip_raw, = struct.unpack_from("!I", item_data, 6)
    ip_str = ".".join(map(str, ip_raw.to_bytes(4, "big")))

    vendor_id, device_type, product_code = struct.unpack_from("<HHH", item_data, 18)
    major, minor = struct.unpack_from("BB", item_data, 24)
    status, serial = struct.unpack_from("<HI", item_data, 26)
    vname, vstatus = get_vendor_network_status(vendors, vendor_id)

    prod_name_len = item_data[32]
    pname_b = item_data[33:33 + prod_name_len]
    pname = pname_b.decode(errors="ignore")
    ps, pn, pv = get_product_details(vname, pname)

    item = {
        "protocol_version": protocol_version,
        "ip": ip_str,
        "port": sin_port,
        "vendor_id": vendor_id,
        "vendor_name": vname,
        "vendor_status": vstatus,
        "device_type": device_type,
        "device_type_name": get_device(devices, device_type),
        "product_code": product_code,
        "product_full_name": pname,
        "product_series": ps,
        "product_name": pn,
        "product_version": pv,
        "revision": f"{major}.{minor}",
        "status": status,
        "serial": serial,
        "status_flags": decode_status(status),
    }

    if 33 + prod_name_len < len(item_data):
        item["state"] = item_data[33 + prod_name_len]

    return item

def parse_list_identity(data: str, vendors: pd.DataFrame, devices: pd.DataFrame) -> dict:
    """
    Parse a full ListIdentity response (encapsulation + identity items).
    """
    b = bytes.fromhex(data)
    header = parse_encapsulation_header(b)
    payload = header["payload"]

    lid = {
        "command": header["command"],
        "session": header["session"],
        "status": header["status"],
        "options": header["options"],
    }

    if not payload:
        return lid

    item_count, = struct.unpack_from("<H", payload, 0)
    items = []
    offset = 2

    for _ in range(item_count):
        item_type, item_length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        item_data = payload[offset:offset + item_length]
        offset += item_length

        if item_type == 0x0C:  # Identity item
            items.append(parse_list_identity_item(item_data, vendors, devices))
        else:
            items.append({"item_type": item_type, "raw": base64.b64encode(item_data).decode("utf-8")})
    lid["items"] = items
    return lid

def fingerprint(row: pd.Series, vendors: pd.DataFrame, devices: pd.DataFrame):
    if pd.notna((idt := get_record_field(row, "ListIdentityRaw_Response"))):
        return parse_list_identity(idt, vendors, devices)

def make_ethernetip_fp_handler_from_db() -> ModuleHandler:
    def wrapper(mod: Module) -> None:
        repo = mod.repo()
        vendors = repo.get_records(source="eip_vendors", prefix=None)
        devices = repo.get_records(source="eip_devices", prefix=None)
        def handler(df: pd.DataFrame):
            fps = []
            for _,r in df.iterrows():
                if fp := fingerprint(r, vendors, devices):
                    fps.append(mod.make_fingerprint(r, fp, "ethernetip"))
            repo.fingerprint(*fps)

        q = query_records("zgrab2", protocol="ethernetip")
        mod.with_pbar(handler, q)
    return wrapper

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "ethernetip", make_ethernetip_fp_handler_from_db())