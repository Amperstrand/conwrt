"""ubus HTTP JSON-RPC client for OpenWrt.

Provides a Python interface to OpenWrt's ubus IPC bus over HTTP (rpcd).
Used as an alternative transport to SSH for device configuration.

Authentication: username/password via rpcd session.login, returns a session
token used for subsequent calls.

Transport mapping:
  SSH:    subprocess.run(ssh_cmd(ip, shell_script))
  ubus:   UbusClient(ip).login(user, pw) → client.uci_set(...) → client.uci_commit(...)

Limitations:
  - No file transfer (ubus has no file I/O)
  - No package installation (no opkg in default ubus objects)
  - No firmware flashing
  - ShellCommand ops fall back to ubus exec (if available) or are skipped
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any


class UbusError(Exception):
    pass


class UbusAuthError(UbusError):
    pass


class UbusCallError(UbusError):
    def __init__(self, message: str, code: int = -1):
        super().__init__(message)
        self.code = code


class UbusClient:
    def __init__(self, host: str, port: int = 80, timeout: int = 10):
        self.url = f"http://{host}:{port}/ubus"
        self.timeout = timeout
        self.token: str | None = None
        self._id = 0

    def login(self, username: str = "root", password: str = "") -> str:
        result = self._call(
            "00000000000000000000000000000000",
            "session", "login",
            {"username": username, "password": password},
        )
        if "ubus_rpc_session" not in result:
            raise UbusAuthError("login failed: no session token in response")
        token: str = result["ubus_rpc_session"]
        self.token = token
        return token

    def call(self, object_name: str, method: str, params: dict | None = None) -> dict:
        if not self.token:
            raise UbusError("not authenticated — call login() first")
        return self._call(self.token, object_name, method, params or {})

    def uci_get(self, config: str, section: str = "", option: str = "") -> dict:
        params: dict[str, Any] = {"config": config}
        if section:
            params["section"] = section
        if option:
            params["option"] = option
        return self.call("uci", "get", params)

    def uci_set(self, config: str, section: str, values: dict[str, Any]) -> dict:
        return self.call("uci", "set", {
            "config": config,
            "section": section,
            "values": values,
        })

    def uci_add(self, config: str, type_name: str, name: str = "", values: dict[str, Any] | None = None) -> dict:
        params: dict[str, Any] = {"config": config, "type": type_name}
        if name:
            params["name"] = name
        if values:
            params["values"] = values
        return self.call("uci", "add", params)

    def uci_delete(self, config: str, section: str, option: str = "") -> dict:
        params: dict[str, Any] = {"config": config, "section": section}
        if option:
            params["option"] = option
        return self.call("uci", "delete", params)

    def uci_commit(self, config: str) -> dict:
        return self.call("uci", "commit", {"config": config})

    def uci_changes(self, config: str = "") -> dict:
        params: dict[str, Any] = {}
        if config:
            params["config"] = config
        return self.call("uci", "changes", params)

    def service_action(self, name: str, action: str) -> dict:
        return self.call("rc", action, {"name": name})

    def board(self) -> dict:
        return self.call("system", "board")

    def info(self) -> dict:
        return self.call("system", "info")

    def _call(self, token: str, object_name: str, method: str, params: dict) -> dict:
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "call",
            "params": [token, object_name, method, params],
        }).encode()

        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise UbusError(f"HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise UbusError(f"connection failed: {e.reason}") from e

        result = data.get("result")
        if result is None:
            raise UbusCallError(f"no result in response: {data}")

        if isinstance(result, list) and len(result) >= 1:
            code = result[0]
            if code != 0:
                raise UbusCallError(
                    f"ubus call {object_name}.{method} failed with code {code}",
                    code=code,
                )
            return result[1] if len(result) > 1 else {}

        raise UbusCallError(f"unexpected result format: {result}")
