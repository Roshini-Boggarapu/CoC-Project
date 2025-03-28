import os
import struct
import hashlib
import uuid
import base64
from datetime import datetime, timezone

AES_KEY = b"R0chLi4uLi4uLi4="  # base64 encoded, will decode in actual use
BLOCKCHAIN_FILE = os.getenv("BCHOC_FILE_PATH", "bchoc_blockchain.bin")

INITIAL_BLOCK_STRUCT = "32s d 32s 32s 12s 12s 12s I"

def pad_bytes(s, length):
    return s.encode("utf-8").ljust(length, b"\0")

def create_genesis_block():
    prev_hash = b"0" * 32
    timestamp = 0.0
    case_id = b"0" * 32
    evidence_id = b"0" * 32
    state = pad_bytes("INITIAL", 12)
    creator = b"\0" * 12
    owner = b"\0" * 12
    reserved = b"\0" * 12
    data = b"Initial block\0"
    d_length = len(data)
    packed = struct.pack(INITIAL_BLOCK_STRUCT, prev_hash, timestamp, case_id,
                         evidence_id, state, creator, owner, reserved, d_length)
    return packed + data

def init_blockchain():
    if not os.path.exists(BLOCKCHAIN_FILE):
        with open(BLOCKCHAIN_FILE, "wb") as f:
            block = create_genesis_block()
            f.write(block)
        print("> Blockchain file not found. Created INITIAL block.")
    else:
        with open(BLOCKCHAIN_FILE, "rb") as f:
            data = f.read()
            if data[:32] == b"0" * 32:
                print("> Blockchain file found with INITIAL block.")
            else:
                print("> Invalid blockchain file found.")
                exit(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        init_blockchain()
    else:
        print("Usage: python3 bchoc.py init")
