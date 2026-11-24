"""Test vectors for derive_device_secret (#763 P1 — secret derivation had
zero vectors; crypto correctness is precisely what unit vectors pin).

Three layers of ground truth:

1. EXTERNAL vectors — the publicly known answers the implementation must
   reproduce: BIP39 canonical seed, RFC 5869 HKDF-SHA256 test case, and
   the secp256k1 generator point (scalar 1 -> G).
2. FLEET-STABILITY golden vector — the full derive_all() output for a
   fixed (mnemonic, MAC) pair, pinned so any refactor that changes fleet
   identity derivations fails loudly instead of silently re-keying every
   device. Uses the BIP39 test mnemonic, never a real fleet seed.
3. PROPERTIES — determinism, MAC-format normalization, HKDF key
   separation across MACs, scalar range, CGNAT/CGNAT-shape and
   local-admin-bit invariants of the derived identities.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from derive_device_secret import (  # noqa: E402
    SECP256K1_N,
    _hkdf_expand,
    _hkdf_extract,
    _mnemonic_to_seed,
    derive_all,
    derive_device_secret,
    derive_ipv4,
    derive_mac_addr,
)
from generate_nostr_keypair import derive_pubkey_compressed  # noqa: E402

# The canonical BIP39 test mnemonic (public vector, never a fleet secret).
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_MAC = "aa:bb:cc:dd:ee:ff"


class TestExternalVectors:
    def test_bip39_canonical_seed(self):
        # Publicly known BIP39 vector: this exact mnemonic + passphrase-less
        # salt "mnemonic" must give the canonical 64-byte seed.
        seed = _mnemonic_to_seed(TEST_MNEMONIC)
        assert seed.hex() == (
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        )

    def test_hkdf_rfc5869_test_case_1(self):
        # RFC 5869 A.1 (SHA-256): IKM 0x0b*22, salt 000102...0c, info f0f1..f9
        ikm = b"\x0b" * 22
        salt = bytes(range(0x00, 0x0d))
        info = bytes(range(0xf0, 0xfa))
        prk = _hkdf_extract(salt, ikm)
        assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        okm = _hkdf_expand(prk, info, 42)
        assert okm.hex() == (
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

    def test_secp256k1_generator(self):
        # Scalar 1 must derive the compressed generator point
        # 0279BE667E... (the single best-known secp256k1 value).
        pub = derive_pubkey_compressed((1).to_bytes(32, "big"))
        assert pub.hex().lower() == (
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )


class TestFleetStabilityGolden:
    """Pinned full-derivation output — changes here re-key the fleet."""

    def test_golden_secret(self):
        s = derive_device_secret(TEST_MNEMONIC, TEST_MAC)
        assert s.hex() == (
            "cfbcf700c0671584735305c5143a8b583d0ade1383e0da575d84befac5e97495"
        )

    def test_golden_derive_all(self):
        d = derive_all(TEST_MNEMONIC, TEST_MAC)
        assert d["private_key"] == "cfbcf700c0671584735305c5143a8b583d0ade1383e0da575d84befac5e97495"
        assert d["npub"] == "npub15wnqcrf4a4c9jzga23y9s2hst7n23cc9t568qw73l6w7nr902q8sxv8xmc"
        assert d["ipv4"] == "100.74.26.1"
        assert d["root_password"] == "Hotel-Charlie-Echo-40"
        assert d["wifi_password"] == "India-Xray-8834"
        assert d["mac_br_lan"] == "92:16:a1:aa:40:28"


class TestProperties:
    def test_deterministic(self):
        a = derive_device_secret(TEST_MNEMONIC, TEST_MAC)
        b = derive_device_secret(TEST_MNEMONIC, TEST_MAC)
        assert a == b

    @pytest.mark.parametrize("mac", [
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "aabbccddeeff",
        "aa-bb-cc-dd-ee-ff",
        "aa.bb.cc.dd.ee.ff",
    ])
    def test_mac_format_normalized(self, mac):
        assert derive_device_secret(TEST_MNEMONIC, mac) == \
            derive_device_secret(TEST_MNEMONIC, TEST_MAC)

    def test_key_separation_across_macs(self):
        secrets = {derive_device_secret(TEST_MNEMONIC, f"aa:bb:cc:dd:ee:{i:02x}").hex()
                   for i in range(16)}
        assert len(secrets) == 16, "one device's MAC must not determine another's secret"

    def test_scalar_range(self):
        s = int.from_bytes(derive_device_secret(TEST_MNEMONIC, TEST_MAC), "big")
        assert 0 < s < SECP256K1_N

    def test_ipv4_is_cgnat(self):
        d = derive_all(TEST_MNEMONIC, TEST_MAC)
        first, second = (int(o) for o in d["ipv4"].split(".")[:2])
        assert first == 100 and 64 <= second <= 127, "derived LAN IPv4 must sit in 100.64/10"

    def test_derived_macs_local_admin_and_distinct(self):
        d = derive_all(TEST_MNEMONIC, TEST_MAC)
        macs = [d["mac_br_lan"], d["mac_wlan0"], d["mac_wlan1"]]
        for m in macs:
            first_byte = int(m.split(":")[0], 16)
            assert first_byte & 0x02, "derived MAC must set the local-admin bit"
            assert not (first_byte & 0x01), "derived MAC must stay unicast"
        assert len(set(macs)) == 3, "per-interface MACs must differ"
        assert all(m != TEST_MAC for m in macs)
