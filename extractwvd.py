import argparse
import json
from enum import Enum
from pathlib import Path
from construct import BitStruct, Bytes, Const
from construct import Enum as CEnum
from construct import Flag, If, Int8ub, Int16ub, Optional, Padded, Padding, Struct, this
from Cryptodome.PublicKey import RSA
from cdm.wks import ClientIdentification

class DeviceTypes(Enum):
    CHROME = 1
    ANDROID = 2

WidevineDeviceStruct = Struct(
    'signature' / Const(b'WVD'),
    'version' / Int8ub,
    'type' / CEnum(
        Int8ub,
        **{t.name: t.value for t in DeviceTypes}
    ),
    'security_level' / Int8ub,
    'flags' / Padded(1, Optional(BitStruct(
        Padding(7),
        'send_key_control_nonce' / Flag
    ))),
    'private_key_len' / Int16ub,
    'private_key' / Bytes(this.private_key_len),
    'client_id_len' / Int16ub,
    'client_id' / Bytes(this.client_id_len),
    'vmp_len' / Optional(Int16ub),
    'vmp' / If(this.vmp_len, Optional(Bytes(this.vmp_len)))
)

WidevineDeviceStructVersion = 1

def parse_args():
    parser = argparse.ArgumentParser(description='Widevine Device Information Parser')
    parser.add_argument('file', type=Path, help='Path to WVD file')
    return parser.parse_args()

def write_key_and_blob_files(out_dir, device):
    private_key_file = out_dir / 'device_private_key'
    print(f'\n[INFO] Writing private key to: {private_key_file}')
    private_key = RSA.import_key(device.private_key)
    private_key_file.write_text(private_key.export_key('PEM').decode())

    client_id_blob_file = out_dir / 'device_client_id_blob'
    print(f'[INFO] Writing client ID blob to: {client_id_blob_file}')
    client_id_blob_file.write_bytes(device.client_id)

    if device.vmp:
        vmp_blob_file = out_dir / 'device_vmp_blob'
        print(f'[INFO] Writing VMP blob to: {vmp_blob_file}')
        vmp_blob_file.write_bytes(device.vmp)

def write_json_file(out_dir, name, client_id, device):
    wv_json_file = out_dir / 'wv.json'
    description = f'{name} ({client_id.Token._DeviceCertificate.SystemId})'
    print(f'[INFO] Writing JSON file to: {wv_json_file}')
    wv_json_file.write_text(json.dumps({
        'name': name,
        'description': description,
        'security_level': device.security_level,
        'session_id_type': device.type.lower(),
        'private_key_available': True,
        'vmp': bool(device.vmp),
        'send_key_control_nonce': device.type == DeviceTypes.ANDROID
    }, indent=2))

def main():
    args = parse_args()

    name = args.file.with_suffix('').name
    out_dir = Path.cwd() / 'cdm' / 'devices' / 'android_generic'
    out_dir.mkdir(parents=True, exist_ok=True)

    with args.file.open('rb') as fd:
        device = WidevineDeviceStruct.parse_stream(fd)

    print(f'\n[INFO] Starting Widevine Device Information Parsing')
    write_key_and_blob_files(out_dir, device)

    client_id = ClientIdentification()
    client_id.ParseFromString(device.client_id)

    write_json_file(out_dir, name, client_id, device)

    print('[INFO] Done')

if __name__ == '__main__':
    main()
