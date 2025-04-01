#!/usr/bin/env python3
import os
import struct
import argparse
import base64
from Crypto.Cipher import AES
import uuid
import hashlib
import maya
import sys

# Constants
BLOCKCHAIN_FILE = os.getenv("BCHOC_FILE_PATH", "bchocBlockchain.bin")
AES_KEY = b"R0chLi4uLi4uLi4="
PASSWORDS = {
    "P80P": "POLICE",
    "L76L": "LAWYER",
    "A65A": "ANALYST",
    "E69E": "EXECUTIVE",
    "C67C": "CREATOR",
}

# Block Structure Format
BLOCK_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_SIZE = struct.calcsize(BLOCK_FORMAT)

def encryptData(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    paddedData = data.ljust(16, b'\0')
    return cipher.encrypt(paddedData)
    
def decryptData(data: bytes) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(data).rstrip(b'\0').decode()
    
def hashBlock(prevHash, unixTimestamp, caseId, itemId, state, creator, owner, data):
    blockContent = struct.pack(BLOCK_FORMAT, prevHash, unixTimestamp, caseId, itemId, state, creator, owner, data)
    return hashlib.sha256(blockContent).digest()
    
def padBytes(s, length):
    """Pads the string 's' to the specified byte length using null bytes."""
    return s.encode("utf-8").ljust(length, b"\0")

def createGenesisBlock():
    """Creates the genesis block."""
    prevHash = b"0" * 32
    unixTimestamp = 0.0
    caseId = b"0" * 32
    evidenceId = b"0" * 32
    state = padBytes("INITIAL", 12)
    creator = b"\0" * 12
    owner = b"\0" * 12
    data = b"Initial block\0"
    dataLength = len(data)
    packed = struct.pack(
        BLOCK_FORMAT, prevHash, unixTimestamp, caseId, evidenceId, state, creator, owner, dataLength
    )
    return packed + data

def initBlockchain():
    """Initializes the blockchain with the genesis block."""
    if os.path.exists(BLOCKCHAIN_FILE):
        print("Blockchain file found with INITIAL block.")
        return
    with open(BLOCKCHAIN_FILE, "wb") as f:
        genesisBlock  = createGenesisBlock()  # Use the createGenesisBlock() to get the genesis block
        f.write(genesisBlock)
        print("Blockchain file not found. Created INITIAL block.")
        
def addCase(caseId, itemId, creator, password):
    if password not in PASSWORDS:
        print("Invalid password")
        os._exit(1)
    encryptedCaseId = encryptData(uuid.UUID(caseId).bytes)
    encrpyedItemId = encryptData(struct.pack("I", int(itemId)))
    timestamp = maya.now().datetime(to_timezone='UTC')  # Get UTC time
    unixTimestamp = timestamp.timestamp()  # This is a float representing the Unix timestamp
    formattedTimestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')  # Formatting to the required format
    state = b"CHECKEDIN\0\0\0"
    creator = creator.encode().ljust(12, b'\0')
    owner = creator
    dataLength = len(caseId) + len(itemId)
    prevHash = b"0"*32
    with open(BLOCKCHAIN_FILE, "ab") as f:
        block = struct.pack(BLOCK_FORMAT, prevHash, unixTimestamp, encryptedCaseId, encrpyedItemId, state, creator, owner, dataLength)
        f.write(block)
    print(f"Added item: {itemId}\nStatus: CHECKEDIN\nTime of action: {formattedTimestamp}")

# Main function
def main():
    # CLI Argument Parsing
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init")
    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("-c", "--caseId", required=True)
    add_parser.add_argument("-i", "--itemId", required=True)
    add_parser.add_argument("-g", "--creator", required=True)
    add_parser.add_argument("-p", "--password", required=True)

    args = parser.parse_args()

    if args.command == "init":
        initBlockchain()
    elif args.command == "add":
        addCase(args.caseId, args.itemId, args.creator, args.password)


if __name__ == "__main__":
    main()
