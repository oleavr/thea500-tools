#!/usr/bin/env python3

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from enum import Enum
import io
import os
from pathlib import Path
import struct
import sys


class OperationType(Enum):
    UPDATE_FILE = 2
    UNLINK_FILE = 3
    SYMLINK_FILE = 4
    REMOVE_DIRECTORY = 5
    EXECUTE_PAYLOAD = 6


pubkey_n_raw = [
    0xd1, 0xfc, 0x8c, 0x2e, 0xce, 0xc0, 0x1e, 0x44, 0xfb, 0x49, 0x30, 0xe8, 0xc2, 0x58, 0x84, 0xaf,
    0x5c, 0xcf, 0xa4, 0x13, 0x9b, 0x75, 0x8b, 0x10, 0x1c, 0x32, 0x98, 0x74, 0x7c, 0x66, 0xb8, 0xa5,
    0x85, 0xae, 0xca, 0xa2, 0x54, 0xe4, 0x75, 0x72, 0x88, 0xa5, 0x8f, 0xdb, 0xd9, 0xfa, 0x70, 0x95,
    0xc0, 0xaf, 0xca, 0x69, 0x07, 0x8e, 0x45, 0x78, 0x96, 0xd1, 0x2a, 0xa1, 0x81, 0x5a, 0x49, 0x84,
    0xe2, 0x45, 0x46, 0xf7, 0xcf, 0x43, 0xb1, 0xe3, 0x46, 0xa3, 0x36, 0xe8, 0x38, 0xaf, 0xf5, 0xc9,
    0xff, 0x78, 0xa2, 0x0f, 0xa7, 0xc6, 0x9c, 0x4b, 0xff, 0x9c, 0xa4, 0xfd, 0x9c, 0xc0, 0xda, 0xd3,
    0x4f, 0xf1, 0x51, 0x00, 0x43, 0x88, 0xe7, 0xe0, 0x51, 0xbe, 0x2c, 0x4e, 0x5b, 0xa5, 0x31, 0x61,
    0x32, 0xb2, 0x2d, 0x2d, 0x28, 0x81, 0x63, 0x26, 0x28, 0xfb, 0x98, 0x13, 0xf0, 0x8b, 0x3f, 0xc0,
    0x53, 0x52, 0x2f, 0x5f, 0x20, 0xbc, 0x26, 0x9e, 0x48, 0x1c, 0xb8, 0x4f, 0x77, 0x54, 0x04, 0x32,
    0x62, 0x8a, 0x37, 0xbb, 0x0c, 0x49, 0xa0, 0xa0, 0x96, 0xbd, 0x54, 0xf5, 0xd4, 0x9e, 0xee, 0x03,
    0x4a, 0x8b, 0xf7, 0x0b, 0x41, 0x4b, 0x36, 0xd2, 0xeb, 0x87, 0x8c, 0x10, 0x47, 0xe5, 0x3a, 0x82,
    0x3a, 0x07, 0x70, 0xd3, 0xfc, 0x63, 0xc3, 0xd6, 0xf6, 0x03, 0x09, 0x05, 0x0c, 0x2f, 0x81, 0x9a,
    0x47, 0x50, 0x04, 0x2e, 0x80, 0x50, 0x81, 0x1f, 0xde, 0x73, 0x7e, 0x89, 0xc5, 0x1b, 0xd4, 0x5a,
    0xac, 0x47, 0x74, 0x15, 0x40, 0xe3, 0xc8, 0xf5, 0xbd, 0xce, 0x10, 0xc5, 0xb0, 0x06, 0xbc, 0x26,
    0xef, 0x74, 0x41, 0xd6, 0xd6, 0xe6, 0xa8, 0x4d, 0x76, 0xf7, 0x87, 0x5e, 0x43, 0x90, 0x6c, 0xa0,
    0x44, 0xbe, 0x0e, 0xd4, 0xad, 0xab, 0x13, 0xb1, 0x9c, 0x35, 0x2e, 0x35, 0xb9, 0xe0, 0x0b, 0x73
]
pubkey_n = int.from_bytes(pubkey_n_raw, byteorder="big")
pubkey_e = int.from_bytes([ 0x01, 0x00, 0x01 ], byteorder="big")

pkcs1_rsa_sha256_id = bytearray([
    0x30, 0x31,
    0x30, 0x0d,
    0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00,
    0x04, 0x20
])


def dump(firmware, output_dir):
    version, payload = decrypt(firmware)

    cursor = io.BytesIO(payload)

    product, version_again, num_operations, header_size = struct.unpack("<IIII", cursor.read(16))
    assert product == 0x010000a5
    assert version_again == version
    cursor.seek(header_size)

    print(f"Firmware update has {num_operations} operations:")

    for i in range(num_operations):
        op_size, raw_op_type, op_arg, op_path_size, op_extra_size = struct.unpack("<IIIII", cursor.read(20))
        op_type = OperationType(raw_op_type)
        op_path = cursor.read(op_path_size).decode("utf-8")[:-1]

        alignment_remainder = op_path_size % 4
        if alignment_remainder != 0:
            alignment_padding = 4 - alignment_remainder
            cursor.seek(alignment_padding, os.SEEK_CUR)
        else:
            alignment_padding = 0

        op_data = cursor.read(op_size - (20 + op_path_size + alignment_padding + op_extra_size))

        print(f"\t{op_type} arg={op_arg} path=\"{op_path}\"")

        if op_type is OperationType.UPDATE_FILE:
            h = hashes.Hash(hashes.SHA256())
            h.update(op_data)
            digest = h.finalize().hex()
            print(f"\t\tdata=({len(op_data)} bytes, SHA-256: {digest})")

            if output_dir is not None:
                target_path = output_dir / op_path[1:]
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(op_data)
                print("\t\twritten to:", target_path)

        op_extra_data = cursor.read(op_extra_size)

    assert len(cursor.read()) == 0


def decrypt(firmware):
    with firmware.open(mode="rb") as infile:
        file_size = firmware.stat().st_size

        magic, product, version, header_size = struct.unpack("<IIII", infile.read(16))
        assert magic == 0x50cd50cd
        assert product == 0x010000a5
        assert header_size >= 16
        print("Version:", version)
        infile.seek(header_size)

        (params_size,) = struct.unpack(">I", infile.read(4))
        encrypted_params = int.from_bytes(infile.read(params_size), byteorder="big")
        raw_params = bytearray.fromhex(hex(pow(encrypted_params, pubkey_e, pubkey_n))[-(88 * 2):])

        aes256_key = raw_params[:32]
        aes256_iv = raw_params[32:48]
        hmac_key = raw_params[48:80]
        (confirmed_version,) = struct.unpack("<I", raw_params[80:84])
        assert confirmed_version == version

        encrypted_payload = infile.read(file_size - (header_size + 4 + params_size) - len(pubkey_n_raw))
        raw_signature = infile.read()
        assert len(raw_signature) == len(pubkey_n_raw)

        cipher = Cipher(algorithms.AES(aes256_key), modes.CBC(aes256_iv))
        decryptor = cipher.decryptor()
        payload = decryptor.update(encrypted_payload) + decryptor.finalize()

        unused_space_in_last_block = payload[-1]
        block_size = 16
        assert unused_space_in_last_block <= block_size
        payload = payload[:-unused_space_in_last_block]

        signature = int.from_bytes(raw_signature, byteorder="big")
        verify_signature(payload, signature, hmac_key)

        return version, payload


def verify_signature(data, encrypted_signature, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    digest = h.finalize()

    padding_needed = len(pubkey_n_raw) - (3 + len(pkcs1_rsa_sha256_id) + len(digest))
    wrapped_digest = bytearray([ 0x00, 0x01 ]) \
            + (padding_needed * bytearray([ 0xff ])) \
            + bytearray([ 0x00 ]) \
            + pkcs1_rsa_sha256_id \
            + digest
    expected_signature = int.from_bytes(wrapped_digest, byteorder="big")
    signature = pow(encrypted_signature, pubkey_e, pubkey_n)
    assert signature == expected_signature


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/theA500-mini-upgrade-x.a5u [output_dir]", file=sys.stderr)
        sys.exit(1)
    firmware = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else None
    dump(firmware, output_dir)
