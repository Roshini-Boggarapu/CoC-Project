#!/usr/bin/env python3

import sys
import struct
import hashlib
import argparse
import os
import string

partition_types = {
    "00": "Empty",
    "01": "FAT12",
    "04": "FAT16 <32M",
    "05": "Extended",
    "06": "FAT16",
    "07": "HPFS/NTFS/exFAT",
    "A5": "FreeBSD",
    "A8": "Mac OS X",
    "A9": "NetBSD",
}

def compute_hashes(file_path):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found")
        return

    hash_functions = {
        "MD5": hashlib.md5(),
        "SHA-256": hashlib.sha256(),
        "SHA-512": hashlib.sha512()
    }

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for hasher in hash_functions.values():
                hasher.update(chunk)

# Generative AI Used: ChatGPT (OpenAI, March 18, 2025)
# Purpose: Needed help switching my names from upper case to lower case
# Prompt: "Can you fix the function so it prints in lower case instead of upper case"
    for name, hasher in hash_functions.items():
        hash_filename = f"{name}-{os.path.basename(file_path)}.txt"
        with open(hash_filename, "w") as hashfile:
            hashfile.write(hasher.hexdigest().lower().strip())

def read_sector(file, sector_number, sector_size=512):
    file.seek(sector_number * sector_size)
    return file.read(sector_size)


# Generative AI Used: ChatGPT (OpenAI, March 19, 2025)
# Purpose: Needed help parsing GPT values
# Prompt: "I am not getting the right has values for GPT can you rewrite my parse_gpt function so it I get the right values as per the instruction?"
#Prompt: "can you help me seperate parse guid into a seperate function?"
def parse_guid(raw_guid):
    part1 = raw_guid[10:16][::-1].hex()  
    part2 = raw_guid[8:10][::-1].hex()  
    part3 = raw_guid[6:8][::-1].hex()  
    part4 = raw_guid[4:6][::-1].hex()       
    part5 = raw_guid[0:4][::-1].hex()     
    return f"{part1}{part2}{part3}{part4}{part5}"

def parse_gpt(file):
    gpt_header = read_sector(file, 1)
    if gpt_header[:8] != b"EFI PART":
        return []

    num_entries = struct.unpack_from("<I", gpt_header, 80)[0]
    entry_size = struct.unpack_from("<I", gpt_header, 84)[0]
    partition_table_start = struct.unpack_from("<Q", gpt_header, 72)[0] * 512

    partitions = []

    for i in range(num_entries):
        entry_offset = partition_table_start + (i * entry_size)
        file.seek(entry_offset)
        entry = file.read(entry_size)

        if len(entry) < 48 or entry[:16] == b"\x00" * 16:
            continue

        partition_type_guid = parse_guid(entry[:16])
        lba_start = struct.unpack_from("<Q", entry, 32)[0]
        lba_end = struct.unpack_from("<Q", entry, 40)[0]
        partition_name = entry[56:128].decode('utf-16').strip('\x00')

        partitions.append({
            "type_guid": partition_type_guid,
            "lba_start": lba_start,
            "lba_end": lba_end,
            "partition_name": partition_name or "Unknown"
        })

    return partitions

def read_boot_record(image_path, start_byte, offset):
    with open(image_path, 'rb') as f:
        f.seek(start_byte + offset)
        data = f.read(16)

        hex_values = ' '.join(f"{b:02X}" for b in data)
        ascii_values = ''.join(chr(b) if chr(b) in string.printable and b >= 32 else '.' for b in data)

    return hex_values, ascii_values


def parse_mbr(image_path):
    partitions = []
    with open(image_path, 'rb') as f:
        f.seek(0x1BE)
        for i in range(4):
            entry = f.read(16)
            if len(entry) < 16:
                break

            part_type = entry[4]
            if part_type == 0x00:
                continue

# Generative AI Used: ChatGPT (OpenAI, March 24, 2025)
# Purpose: I kept getting partition ID incorrect for test case#8
# Prompt: "Why does it keep saying partition ID wrong for (A9)?"
            type_hex = f"({part_type:02x})"
            type_name = partition_types.get(f"{part_type:02X}", "Unknown")

            start_sector = struct.unpack("<I", entry[8:12])[0]
            total_sectors = struct.unpack("<I", entry[12:16])[0]
            start_byte = start_sector * 512

            partitions.append({
                "type_hex": type_hex,
                "type_name": type_name,
                "start_byte": start_byte,
                "start_sector": start_sector,
                "size": total_sectors * 512
            })
    return partitions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Path to raw disk image")
    parser.add_argument("-o", "--offsets", nargs="*", type=int, help="Offset values for boot record extraction", default=[])
    args = parser.parse_args()

    if not os.path.exists(args.file):
        sys.exit(1)

    compute_hashes(args.file)

    with open(args.file, "rb") as f:
        mbr = read_sector(f, 0)
        if mbr[0x1FE:0x200] != b"\x55\xAA":
            sys.exit(1)

        # GPT parsing
        if mbr[0x1BE + 4] == 0xEE:
            partitions = parse_gpt(f)
            for idx, part in enumerate(partitions, 1):
                print(f"Partition number: {idx}")
                print(f"Partition Type GUID: {part['type_guid']}")
                print(f"Starting LBA in hex: 0x{part['lba_start']:X}")
                print(f"Ending LBA in hex: 0x{part['lba_end']:X}")
                print(f"Starting LBA in Decimal: {part['lba_start']}")
                print(f"Ending LBA in Decimal: {part['lba_end']}")
                print(f"Partition name: {part['partition_name']}")
                print()

            for idx, part in enumerate(partitions):
                for offset in args.offsets:
                    byte_offset = part['lba_start'] * 512 + offset
                    hex_data, ascii_data = read_boot_record(args.file, part['lba_start'] * 512, offset)
                    print(f"Partition number: {idx + 1}")
                    print(f"16 bytes of boot record from offset {offset:03}: {hex_data}")
                    print(f"ASCII: {' ' * 40}{ascii_data}")
        #MBR parsing
        else:
            partitions = parse_mbr(args.file)
            for part in partitions:
                print(f"{part['type_hex']}, {part['type_name']}, {part['start_byte']}, {part['size']}")

            for i, offset in enumerate(args.offsets):
                if i < len(partitions):
                    hex_data, ascii_data = read_boot_record(args.file, partitions[i]['start_byte'], offset)
                    print(f"Partition number: {i+1}")
                    print(f"16 bytes of boot record from offset {offset:03}: {hex_data}")
                    print(f"ASCII: {' ' * 40}{ascii_data}")

if __name__ == "__main__":
    main()
