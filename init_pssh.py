import base64
import sys
from pathlib import Path
from google.protobuf.message import DecodeError
from cdm.wks import WidevineCencHeader

# File path to read the raw data
file_path = "your init"

# Read the raw data from the file
raw = Path(file_path).read_bytes()

# Find the offset of 'pssh' in the raw data
pssh_offset = raw.rfind(b'pssh')

if pssh_offset == -1:
    print("[ERROR] 'pssh' not found in the file.")
    sys.exit(1)
else:
    # Extract the PSSH data based on the offset and length information
    _start = max(pssh_offset - 4, 0)
    _end = min(pssh_offset - 4 + raw[pssh_offset - 1], len(raw))
    pssh = raw[_start:_end]

    # Display the PSSH data in base64 format
    print('\n[INFO] PSSH:', base64.b64encode(pssh).decode('utf-8'))
    pssh_b64 = base64.b64encode(pssh)
    print("\n[SUCCESS] PSSH extracted successfully.")

# Check if the PSSH data needs modification
if not pssh[12:28] == bytes([237, 239, 139, 169, 121, 214, 74, 206, 163, 200, 39, 220, 213, 29, 33, 237]):
    print("[Modifying PSSH data...]")
    # Create a new PSSH data with the required modifications
    new_pssh = bytearray([0, 0, 0])
    new_pssh.append(32 + len(pssh))
    new_pssh[4:] = bytearray(b'pssh')
    new_pssh[8:] = [0, 0, 0, 0]
    new_pssh[13:] = [237, 239, 139, 169, 121, 214, 74, 206, 163, 200, 39, 220, 213, 29, 33, 237]
    new_pssh[29:] = [0, 0, 0, 0]
    new_pssh[31] = len(pssh)
    new_pssh[32:] = pssh
    pssh_b64 = base64.b64encode(new_pssh)
    print("[Modified PSSH data:", pssh_b64.decode(), "]")
else:
    print("[PSSH data doesn't need modification.]")

# Parse the modified or original PSSH data using WidevineCencHeader
parsed_init_data = WidevineCencHeader()

try:
    parsed_init_data.ParseFromString(base64.b64decode(pssh_b64))
    print("[PSSH data parsed successfully.]")
except (DecodeError, SystemError) as e:
    print("[Error parsing PSSH data:", e, "]")
    try:
        # Attempt to parse PSSH data from byte offset 32
        id_bytes = parsed_init_data.ParseFromString(base64.b64decode(pssh_b64)[32:])
        print("[PSSH data parsed successfully from byte offset 32.]")
    except DecodeError as de:
        print("[Error parsing PSSH data from byte offset 32:", de, "]")
        sys.exit(1)

# Convert the parsed key_id to a hexadecimal string
key_id_str = ''.join(['{:02x}'.format(b) for b in parsed_init_data.key_id[0]])
print("[Key ID in hexadecimal:", key_id_str, "]")
print("\n[SUCCESS] [Done]\n")