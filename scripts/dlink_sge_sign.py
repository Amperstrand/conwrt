#!/usr/bin/env python3
"""Sign D-Link SGE-encrypted factory images for COVR-X1860 and similar devices.

The OpenWrt build system produces factory.bin images encrypted with AES-128-CBC
via dlink-sge-image, but on macOS the EVP_PKEY_sign call produces all-zero RSA
signatures due to an OpenSSL compatibility bug.  This tool patches the RSA
signatures in an existing factory.bin using the known private key from the GPL
source code, producing a firmware image that passes GetFirmwareValidation on the
device.

Usage:
    python3 dlink_sge_sign.py INPUT.bin OUTPUT.bin

Can also encrypt+sign from a raw (unencrypted) sysupgrade image:
    python3 dlink_sge_sign.py --encrypt COVR-X1860 sysupgrade.bin factory.bin

Binary header layout (HEADER_LEN = 1756 bytes):
    Offset  Size  Field
    0       4     "SHRS" magic
    4       4     payload_length_before (big-endian uint32)
    8       4     payload_length_post (big-endian uint32)
    12      16    salt / AES IV
    28      64    md_vendor  (SHA-512 of plaintext + vendor_key)
    92      64    md_before  (SHA-512 of plaintext)
    156     64    md_post    (SHA-512 of ciphertext)
    220     512   rsa_pub    (unused, all zeros)
    732     512   rsa_sign_before  (RSA-4096 signature of md_before)
    1244    512   rsa_sign_post    (RSA-4096 signature of md_post)
    1756    N     AES-128-CBC encrypted payload
    1756+N  5     footer (0x00 0x00 0x00 0x00 0x30)
"""

import base64
import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils


RSA_KEY_LEN = 512
SHA512_LEN = 64
AES_BLOCK = 16
HEADER_LEN = 1756
FOOTER = b"\x00\x00\x00\x00\x30"

OFF_MAGIC = 0
OFF_PAYLOAD_LEN_BEFORE = 4
OFF_PAYLOAD_LEN_POST = 8
OFF_SALT = 12
OFF_MD_VENDOR = 28
OFF_MD_BEFORE = 92
OFF_MD_POST = 156
OFF_RSA_PUB = 220
OFF_RSA_SIGN_BEFORE = 732
OFF_RSA_SIGN_POST = 1244

# Vendor key deinterleaving pattern from dlink-sge-image.h
_INTERLEAVE_PATTERN = [
    [2, 5, 7, 4, 0, 6, 1, 3],
    [7, 3, 2, 6, 4, 5, 1, 0],
    [5, 1, 6, 7, 3, 0, 4, 2],
    [0, 3, 7, 6, 5, 4, 2, 1],
    [1, 5, 7, 0, 3, 2, 6, 4],
    [3, 6, 2, 5, 4, 7, 1, 0],
    [6, 0, 5, 1, 3, 4, 2, 7],
    [4, 6, 7, 3, 2, 0, 1, 5],
]

# Salt from dlink-sge-image.h (shared across all supported devices)
SALT = bytes([
    0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec,
    0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46,
])

# Per-device configuration: (enk_base64, rsa_key_pem, rsa_key_password)
_DEVICE_CONFIGS = {
    "COVR-X1860": {
        "enk_b64": "NE1oIS1lKzkkIzZkbX49KTMsMWFkJXEybjheJiN6KjIwNjgx",
        "key_pem": (
            "\n-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-256-CBC,34CCF1AEF0C34EAC5FFAE6BCF81ABB8D\n"
            "\n"
            "tAwfCeFe4/lfPC1y55k4XvhGYVnu4EBL1hws4YaruDijYfsIzQQ/LSfj43i82aad\n"
            "07J4OEfl/LcDtEZ8dLC+SYCcE8ejUlr1TnUq2e9P/qLaAupa9ETX/M1z1ApWDKmI\n"
            "EvYTJT7f6kNYPcLTAaaTbkGt9h0prHrmZDq8yvjv1HqefAhn1Hh/UqIq3FEgS/ux\n"
            "dwX1DYyjM/LDv7i3fs0fmODTXiiHJXTsNz+61un52q8eCdDfLjmdytiiWPiKOfqB\n"
            "3wdE5iSFw2RQEGrAkwHWVRaKKln9zGj/RI5Pu9xg7Nofx0EDfgztFCX6WQvDlZNo\n"
            "JKhQtmF9xTeTbuxSqbX667BtAiFkyUdzvaDDv0QFBJDecD9QlR3rfI6Ib+9b1LI1\n"
            "Ahmk0zcW5GV3tQw5lYUIESJXpMK51PFfxQb9SuGpNM+yMQYg03qU104Yq0NjHbPW\n"
            "k6RsfWyVu6k3rUsqL14/TFZ29z0pfScyPqSY5OrQTUTeabG2J7PAzhgprpeZGZ5n\n"
            "pW/BhBNtULlFiABrXKD3Grtxza12qsQuY8ldhd6CIU2joVo2s8y0WvJxnShtKR5H\n"
            "MbDH2DYRunJFb7LUfqpjCX2O1eAI+q6uFZ0pD5Vw5JHRHABn+NGDV0F/Mi1gazqd\n"
            "rF1hlGo10Xm+2SxbUH4ZxTRKXDC5ocHtO2ylKPqbLOFO4I48VBa5kmPs19wpVGov\n"
            "roqbO6Eug8Hwl5CbPttLb11ROekT8O3LUBEtm+rxE007i5YzM4ZSAnOXlG2c0aoi\n"
            "+pFt3z1Byv4eI+piHbjc2A5qYFOLfj/F/qJ+54u4BeYRWf8nhUooYu+avlkzPm8z\n"
            "n47dInw33wyOctQnrEnSG+8D9KtY+/d6gxnS6O0VGeu67NQvmu2n2O8bQdhiHDR6\n"
            "N9Lgs2yHVK+R0PAhpnClFKCsk5xACkZ9e7QZWCFBcwvxFtZL24PjUjFlpR++ZQPX\n"
            "no55rFNq/xR9QN0rYwDZgXNwmYinGrWdEY/qBuRw/88mf9plrauuYo+NjG7wzxHq\n"
            "BXe600Pcu8LZki858AxyqZC1JbwGVjIOGl8JpphxO13pH5sZ5upJwkGvmykdsLFh\n"
            "ru3iI26eq6SwT/BanklzCFWqC882zkCl/MwKkxdLVeqH4JRmq/Bz01XMSARsvGXI\n"
            "GHHJbtyHrkezQnnX6XO4CNkn8ZLcbK/GUPldNnG2qbtuOqad9AHdMJCg8zadVHI9\n"
            "BboA0v0tbxQxBEgveC9A5Jo/azhFl0AKCh+tmguFiA8HVEl1SdRiO9XvMRqYm6w3\n"
            "zCPTrLaE85PLBe1shekJlhEchUN1yRQgZuEiX8Spxgp436dAd61SVsUgypgH1ub9\n"
            "IgPp2C18iRVmi4FXQby10F/Uy/VgVH6aoWTlO9DfVHMGCrjnA4tGdfaQTWDxp1P3\n"
            "5jQpS9bhH33Nqt0/C8cr91ODRzGz9sRqj5bG++FqVz2IvOOzUcVcmkchRYIR6AG2\n"
            "2Drms2+mThV9HAgDrq8kSddw6B6pz+pXaC+pbjXeUPBjHEFzOi1NGM049omLtu73\n"
            "A3Ao9FemHVoExxzdH3LzeMGQM2r/qZMv0PiNfGyNRW3oWZpfCgg7k/BX6pe38emx\n"
            "HFiKzmtfTEu3umOnTRaLGVfWNF5pIaoq175hceT82udOqzGWs+eldB8Cbvogc/qx\n"
            "jpaULJXcb++1FvlEPUpB8RO0gmabzAaOCJMAaAVwEc2q1i6Q6wlotMgG+vw/q7mq\n"
            "04AeP2jthG5gNBLsKvxaSJHZSfsOQvOWiGqylgr72NGK6eWKzMeLVSwnN+rkSsnG\n"
            "QxTVZ++NGdVnC2p4cFXzp7U6wlqEgSyQYHdabAv7Z3NchyUyWWuSinMw+g+8zwxj\n"
            "wlV64L2eIAb8tbqtc+gcC1WggU7GG3G2zp6tcmhgdg/COTc6uh1+0DDv+UkPLjwo\n"
            "TvAQWRAnUlzcDP3jNOGbiuXiQSWT2595BInkIg3D91xcbB5buiNIlD2Dln5xhq/Q\n"
            "BGTJeqhWoeh9ijZY/azgJkGuXr72ghLuf0CQ3j2yP18leg1iYGYI+1eEWkOfc9oo\n"
            "oH21euOQuxejrEs6V38YE+HFJX1vXCurkhaj5QnDbsHfuGlkYxvNXRpMip1VfMBd\n"
            "FHY+0Z7afGdjal7VesQbMswNnh4rpckEI1wCul9Qyhq2oPsR4hQLkfnm0fEM7Ux1\n"
            "CBFpNoH2BFYQ18HN+L5CBUjQVR1KYyAmYFGCgn24x/EKh2OEcd9lL+vTKOkdKCwN\n"
            "ZIa6c3tY/ktmrhC5AY8js6Yu63SXHiTkK4UzAGls3zdIVlH4eQ3uRHBuAEmIMAg+\n"
            "oKeVr058v2dasuzeOEq1kriMkseZA+2zsk42oDh+kj2U5gSusvjxI0ijYMzuNfAq\n"
            "8po/zLlvF8sTHoqhNcf5RpsT+XxchmIcncyE5sXXfDAPoH+LgTPhQG/eRB4qofZ1\n"
            "4KLO+a2kv5mMOOCew6gquvCeZ/W5IFwywzKznw5CA52W7lh8xnyTtgsuaBoN06q2\n"
            "g9nsAhhf7iMMuS687L1ImID0iyzEymLQxlt4qgQLJKeVXCQbS+jkm0Er8mnrTBDL\n"
            "L8Ntj+j4Dz9bIy70p/lw6StmPDFxfQQqMXLiiepdAYFo5A5EYoU41rWDBo+YbRNF\n"
            "H8HcEBD4YIuxQrbNT2K3zGFdaqA9imM9B9YHz+EzfBBfrMtDVV7yme/M9CjECXwc\n"
            "iKdR+QwtucV7Hnk/NOoD/ZOhXf+ybrcxev/C+/O9sHt06vvg1LL8Qr3eb03c5G7E\n"
            "6V//N44JQ69l/Cvzd/TSUUknbVf/0Ydol7kuOuqrfvOcfqdVGY6kR/Phvy8MGTsG\n"
            "9t71xyhFeu0IC1DOUqdV1Srsjw7Vm/wSKcJRcPOJO2lIwyv9SDustR2JRFTjfaBh\n"
            "a3ZJmRn3q/h3e4AUEJ2pyj6HNKviz69bs2JNEw3UKY0muwCJEZaC9vAXIss8FeIB\n"
            "HZKqQC2gv0rjK2RCLVc6cba9/G9tzzx12tOOsQUj/u7mBENKOh+KRNJJ/r9w2zcU\n"
            "B98kPyJI9kjBX2P6U7OE2vNe6djiGOscjuDHyXicaDvMY+1veQEBiDtTXwCvSIo1\n"
            "dJRYMuMfi+aitz9LQOky3yTHTDWZuRhK0b4JNkZYM1F9v8zGhMR4poDrRLsLb9t9\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
        "key_password": b"12345678",
    },
}


def _deinterleave(enk: bytes, length: int) -> bytes:
    pattern_idx = 0
    result = bytearray(length)
    pos = 0
    while pos + 8 <= length:
        pat = _INTERLEAVE_PATTERN[pattern_idx % 8]
        for i in range(8):
            result[pos + i] = enk[pat[i]]
        pos += 8
        pattern_idx += 1
    for i in range(length - pos):
        result[pos + i] = enk[length - pos - i - 1]
    return bytes(result)


def _vendor_key_from_enk(enk_b64: str) -> bytes:
    decoded = base64.b64decode(enk_b64)
    return _deinterleave(decoded, AES_BLOCK)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sign_existing(input_path: str, output_path: str, device: str = "COVR-X1860") -> None:
    cfg = _DEVICE_CONFIGS[device]
    private_key = serialization.load_pem_private_key(
        cfg["key_pem"].encode(), password=cfg["key_password"],
    )

    data = bytearray(Path(input_path).read_bytes())
    magic = bytes(data[OFF_MAGIC:OFF_MAGIC + 4])
    if magic != b"SHRS":
        sys.exit(f"Error: input is not an SGE-encrypted image (magic={magic!r})")

    md_before = bytes(data[OFF_MD_BEFORE:OFF_MD_BEFORE + SHA512_LEN])
    md_post = bytes(data[OFF_MD_POST:OFF_MD_POST + SHA512_LEN])

    old_before = bytes(data[OFF_RSA_SIGN_BEFORE:OFF_RSA_SIGN_BEFORE + RSA_KEY_LEN])
    old_post = bytes(data[OFF_RSA_SIGN_POST:OFF_RSA_SIGN_POST + RSA_KEY_LEN])
    if not (all(b == 0 for b in old_before) and all(b == 0 for b in old_post)):
        print("Warning: existing signatures are non-zero, overwriting")

    sig_before = private_key.sign(
        md_before, asym_padding.PKCS1v15(), asym_utils.Prehashed(hashes.SHA512()),
    )
    sig_post = private_key.sign(
        md_post, asym_padding.PKCS1v15(), asym_utils.Prehashed(hashes.SHA512()),
    )

    data[OFF_RSA_SIGN_BEFORE:OFF_RSA_SIGN_BEFORE + RSA_KEY_LEN] = sig_before
    data[OFF_RSA_SIGN_POST:OFF_RSA_SIGN_POST + RSA_KEY_LEN] = sig_post

    Path(output_path).write_bytes(bytes(data))
    print(f"Signed {input_path} -> {output_path} ({len(data)} bytes)")

    public_key = private_key.public_key()
    public_key.verify(sig_before, md_before, asym_padding.PKCS1v15(), asym_utils.Prehashed(hashes.SHA512()))
    public_key.verify(sig_post, md_post, asym_padding.PKCS1v15(), asym_utils.Prehashed(hashes.SHA512()))
    print("Signatures verified OK")


def encrypt_and_sign(
    input_path: str, output_path: str, device: str = "COVR-X1860",
) -> None:
    cfg = _DEVICE_CONFIGS[device]
    vendor_key = _vendor_key_from_enk(cfg["enk_b64"])
    private_key = serialization.load_pem_private_key(
        cfg["key_pem"].encode(), password=cfg["key_password"],
    )

    plaintext = Path(input_path).read_bytes()
    payload_length_before = len(plaintext)

    pad_len = AES_BLOCK - (payload_length_before % AES_BLOCK)
    if pad_len == 0:
        pad_len = AES_BLOCK
    padded = plaintext + b"\x00" * pad_len
    payload_length_post = len(padded)

    cipher = Cipher(algorithms.AES(vendor_key), modes.CBC(SALT))
    ciphertext = cipher.encryptor().update(padded)

    md_before = _sha512(plaintext)
    md_vendor = _sha512(plaintext + vendor_key)
    md_post = _sha512(ciphertext)

    sig_before = private_key.sign(
        md_before, asym_padding.PKCS1v15(), asym_utils.Prehashed(hashes.SHA512()),
    )
    sig_post = private_key.sign(
        md_post, asym_padding.PKCS1v15(), asym_utils.Prehashed(hashes.SHA512()),
    )

    header = bytearray(HEADER_LEN)
    header[OFF_MAGIC:OFF_MAGIC + 4] = b"SHRS"
    header[OFF_PAYLOAD_LEN_BEFORE:OFF_PAYLOAD_LEN_BEFORE + 4] = struct.pack(">I", payload_length_before)
    header[OFF_PAYLOAD_LEN_POST:OFF_PAYLOAD_LEN_POST + 4] = struct.pack(">I", payload_length_post)
    header[OFF_SALT:OFF_SALT + AES_BLOCK] = SALT
    header[OFF_MD_VENDOR:OFF_MD_VENDOR + SHA512_LEN] = md_vendor
    header[OFF_MD_BEFORE:OFF_MD_BEFORE + SHA512_LEN] = md_before
    header[OFF_MD_POST:OFF_MD_POST + SHA512_LEN] = md_post
    header[OFF_RSA_PUB:OFF_RSA_PUB + RSA_KEY_LEN] = b"\x00" * RSA_KEY_LEN
    header[OFF_RSA_SIGN_BEFORE:OFF_RSA_SIGN_BEFORE + RSA_KEY_LEN] = sig_before
    header[OFF_RSA_SIGN_POST:OFF_RSA_SIGN_POST + RSA_KEY_LEN] = sig_post

    Path(output_path).write_bytes(bytes(header) + ciphertext + FOOTER)
    print(f"Encrypted+signed {input_path} -> {output_path} ({HEADER_LEN + payload_length_post + len(FOOTER)} bytes)")


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 2:
        sign_existing(args[0], args[1])
    elif len(args) == 4 and args[0] == "--encrypt":
        encrypt_and_sign(args[2], args[3], device=args[1])
    else:
        print(
            "Usage:\n"
            "  dlink_sge_sign.py INPUT.bin OUTPUT.bin\n"
            "  dlink_sge_sign.py --encrypt DEVICE_MODEL INPUT.bin OUTPUT.bin\n"
            "\n"
            "Supported devices: " + ", ".join(_DEVICE_CONFIGS),
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
