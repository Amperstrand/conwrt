import struct
import zlib
from pathlib import Path


class UbootEnvBlock:
    def __init__(self):
        self._vars: dict[str, str] = {}
        self._block_size: int = 0
        self._crc_offset: int = 4
        self._padding_byte: int = 0xFF
        self._header_bytes: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes, crc_offset: int = 4) -> "UbootEnvBlock":
        env = cls()
        env._block_size = len(data)
        env._crc_offset = crc_offset
        env._header_bytes = data[:crc_offset]

        if data:
            tail = data[crc_offset:]
            for byte in reversed(tail):
                if byte not in (0x00, 0xFF):
                    env._padding_byte = 0xFF if 0xFF in tail[tail.index(byte) + 1 :] else 0x00
                    break
            else:
                env._padding_byte = 0xFF

        payload = data[crc_offset:]
        end = len(payload)
        for i in range(len(payload) - 1, -1, -1):
            if payload[i] != 0x00 and payload[i] != 0xFF:
                end = i + 1
                break

        content = payload[:end]
        env._vars = {}
        for entry in content.split(b"\x00"):
            entry = entry.strip(b"\x00")
            if not entry:
                continue
            text = entry.decode("ascii", errors="replace")
            eq = text.find("=")
            if eq > 0:
                env._vars[text[:eq]] = text[eq + 1 :]

        return env

    @classmethod
    def from_file(cls, path: str, crc_offset: int = 4) -> "UbootEnvBlock":
        return cls.from_bytes(Path(path).read_bytes(), crc_offset)

    def get(self, key: str) -> str | None:
        return self._vars.get(key)

    def set(self, key: str, value: str) -> None:
        self._vars[key] = value

    def delete(self, key: str) -> bool:
        if key in self._vars:
            del self._vars[key]
            return True
        return False

    def keys(self) -> list[str]:
        return list(self._vars.keys())

    def validate_crc(self) -> bool:
        if self._block_size < self._crc_offset + 4:
            return False
        stored_crc = struct.unpack("<I", self._header_bytes[:4])[0]
        data = self._build_payload()
        computed = zlib.crc32(data) & 0xFFFFFFFF
        return stored_crc == computed

    def _build_payload(self) -> bytes:
        parts = []
        for key, value in self._vars.items():
            parts.append(f"{key}={value}".encode("ascii"))
        content = b"\x00".join(parts)
        if parts:
            content += b"\x00"
        pad_len = self._block_size - self._crc_offset - len(content)
        if pad_len < 0:
            pad_len = 0
        return content + bytes([self._padding_byte] * pad_len)

    def to_bytes(self) -> bytes:
        payload = self._build_payload()
        crc = struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
        header_mid = self._header_bytes[4 : self._crc_offset]
        return crc + header_mid + payload

    def write_file(self, path: str) -> None:
        Path(path).write_bytes(self.to_bytes())
