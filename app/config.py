"""Configuration loading.

Since the scan targets moved into NetBox, the files carry only two things:

  * environment variables (.env)   -> global settings and the credentials that
                                      make up the implicit "default" profiles
  * /app/inventory.yml             -> named credential profiles + the initial
                                      seed of devices to create in NetBox

The device list itself is NOT here: it is read from NetBox on every cycle
(see targets.py), so the operator adds and removes switches from the GUI.
inventory.yml only bootstraps the very first run.

Placeholders of the form ${VAR} / ${VAR:-default} inside inventory.yml are
resolved against the environment, so no secret is ever written into the YAML.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
# The same thing anchored: a value that is *entirely* one placeholder can be
# recorded in the store as a reference to that variable, so the secret itself
# never reaches the database.
_WHOLE_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}$")

TRUE_VALUES = {"1", "true", "yes", "on"}


def env_var_reference(value) -> str | None:
    """Return VAR if `value` is exactly `${VAR}` or `${VAR:-default}`."""
    if value is None:
        return None
    match = _WHOLE_PLACEHOLDER.match(str(value).strip())
    return match.group(1) if match else None


def expand_placeholders(value):
    """Resolve `${VAR}` / `${VAR:-default}` against the environment.

    Public because the store importer needs it: a *secret* read from
    inventory.yml is recorded as a reference to its variable and must stay
    unexpanded, but an ordinary setting such as `snmp_version` has to be the
    resolved value. Storing `"${SNMP_DEFAULT_VERSION:-2c}"` verbatim makes the
    SNMP version match neither "1" nor "2c", and the poller silently falls
    through to SNMPv3.
    """
    return _expand(value)


def env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return default if value is None else value.strip()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in TRUE_VALUES


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _expand(value: Any) -> Any:
    """Recursively resolve ${VAR} / ${VAR:-default} placeholders."""
    if isinstance(value, str):

        def repl(match: re.Match) -> str:
            name, fallback = match.group(1), match.group(2)
            return os.environ.get(name) or (fallback or "")

        return _PLACEHOLDER.sub(repl, value)
    if isinstance(value, list):
        return [_expand(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    return value


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in TRUE_VALUES


# ─────────────────────────────────────────────────────────────────────────────
# Device definitions
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class FortiGateConfig:
    name: str
    host: str
    api_token: str
    port: int = 443
    vdom: str = "root"
    verify_ssl: bool = False
    timeout: int = 20
    sync_device: bool = True

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    @classmethod
    def from_dict(cls, raw: dict) -> "FortiGateConfig":
        return cls(
            name=str(raw.get("name") or raw["host"]).strip(),
            host=str(raw["host"]).strip(),
            api_token=str(raw.get("api_token") or "").strip(),
            port=int(raw.get("port") or 443),
            vdom=str(raw.get("vdom") or "root").strip(),
            verify_ssl=_as_bool(raw.get("verify_ssl"), False),
            timeout=int(raw.get("timeout") or 20),
            sync_device=_as_bool(raw.get("sync_device"), True),
        )


@dataclass
class SwitchConfig:
    name: str
    host: str
    vendor: str = "generic"
    port: int = 161
    snmp_version: str = "2c"
    community: str = ""
    v3_username: str = ""
    v3_security_level: str = "authPriv"
    v3_auth_protocol: str = "SHA"
    v3_auth_password: str = ""
    v3_priv_protocol: str = "AES"
    v3_priv_password: str = ""
    timeout: int = 5
    retries: int = 1
    vlan_indexing: str = "auto"
    uplink_mac_threshold: int = 12

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    @classmethod
    def from_dict(cls, raw: dict, defaults: "ScannerSettings") -> "SwitchConfig":
        version = str(raw.get("snmp_version") or defaults.snmp_default_version).strip()
        # Accept 2, 2c, v2c, 3, v3 ...
        version = version.lower().lstrip("v")
        if version == "2":
            version = "2c"
        return cls(
            name=str(raw.get("name") or raw["host"]).strip(),
            host=str(raw["host"]).strip(),
            vendor=str(raw.get("vendor") or "generic").strip().lower(),
            port=int(raw.get("port") or 161),
            snmp_version=version,
            community=str(raw.get("community") or defaults.snmp_community).strip(),
            v3_username=str(raw.get("v3_username") or defaults.snmp_v3_username).strip(),
            v3_security_level=str(
                raw.get("v3_security_level") or defaults.snmp_v3_security_level
            ).strip(),
            v3_auth_protocol=str(
                raw.get("v3_auth_protocol") or defaults.snmp_v3_auth_protocol
            ).strip(),
            v3_auth_password=str(
                raw.get("v3_auth_password") or defaults.snmp_v3_auth_password
            ),
            v3_priv_protocol=str(
                raw.get("v3_priv_protocol") or defaults.snmp_v3_priv_protocol
            ).strip(),
            v3_priv_password=str(
                raw.get("v3_priv_password") or defaults.snmp_v3_priv_password
            ),
            timeout=int(raw.get("timeout") or defaults.snmp_timeout),
            retries=int(raw.get("retries") or defaults.snmp_retries),
            vlan_indexing=str(raw.get("vlan_indexing") or "auto").strip().lower(),
            uplink_mac_threshold=int(
                raw.get("uplink_mac_threshold") or defaults.snmp_uplink_mac_threshold
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Global settings
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class NetBoxSettings:
    url: str
    token: str
    verify_ssl: bool
    site_name: str
    client_name: str
    default_prefix_len: int


@dataclass
class LifecycleSettings:
    offline_after_hours: int
    delete_after_days: int
    enable_auto_delete: bool
    protected_tag: str


@dataclass
class ApiSettings:
    enabled: bool
    host: str
    port: int


@dataclass
class ScannerSettings:
    interval_minutes: int
    run_on_start: bool
    log_level: str
    dry_run: bool
    state_dir: Path
    snmp_default_version: str
    snmp_community: str
    snmp_timeout: int
    snmp_retries: int
    snmp_uplink_mac_threshold: int
    snmp_v3_username: str
    snmp_v3_security_level: str
    snmp_v3_auth_protocol: str
    snmp_v3_auth_password: str
    snmp_v3_priv_protocol: str
    snmp_v3_priv_password: str


@dataclass
class SeedEntry:
    """A device to create in NetBox on the first run, so the GUI is not empty.

    After it has been seeded once the operator owns it: editing or deleting it
    in NetBox is authoritative and re-seeding never resurrects it.
    """

    name: str
    host: str
    method: str = "snmp"          # snmp | fortios
    credential: str = "default"
    vendor: str = ""
    port: int | None = None


@dataclass
class AppConfig:
    netbox: NetBoxSettings
    lifecycle: LifecycleSettings
    scanner: ScannerSettings
    api: ApiSettings = field(
        default_factory=lambda: ApiSettings(enabled=True, host="0.0.0.0", port=8080)
    )
    # name -> raw profile dict (already expanded from ${VAR})
    credentials: dict[str, dict] = field(default_factory=dict)
    seeds: list[SeedEntry] = field(default_factory=list)
    # Resolved from NetBox at the start of every cycle by targets.load_targets()
    fortigates: list[FortiGateConfig] = field(default_factory=list)
    switches: list[SwitchConfig] = field(default_factory=list)

    @property
    def heartbeat_file(self) -> Path:
        return self.scanner.state_dir / "last_run.json"

    @property
    def seed_state_file(self) -> Path:
        return self.scanner.state_dir / "seeded.json"

    def credential(self, name: str) -> dict:
        """Look up a profile by name, tolerating case and stray whitespace."""
        wanted = (name or "default").strip()
        if wanted in self.credentials:
            return self.credentials[wanted]
        for key, profile in self.credentials.items():
            if key.lower() == wanted.lower():
                return profile
        return {}


class ConfigError(RuntimeError):
    pass


def load_config() -> AppConfig:
    scanner = ScannerSettings(
        interval_minutes=max(1, env_int("SCAN_INTERVAL_MINUTES", 20)),
        run_on_start=env_bool("RUN_ON_START", True),
        log_level=env_str("LOG_LEVEL", "INFO").upper(),
        dry_run=env_bool("DRY_RUN", False),
        state_dir=Path(env_str("STATE_DIR", "/app/state")),
        snmp_default_version=env_str("SNMP_DEFAULT_VERSION", "2c").lower().lstrip("v"),
        snmp_community=env_str("SNMP_COMMUNITY", "public"),
        snmp_timeout=env_int("SNMP_TIMEOUT", 5),
        snmp_retries=env_int("SNMP_RETRIES", 1),
        snmp_uplink_mac_threshold=env_int("SNMP_UPLINK_MAC_THRESHOLD", 12),
        snmp_v3_username=env_str("SNMP_V3_USERNAME"),
        snmp_v3_security_level=env_str("SNMP_V3_SECURITY_LEVEL", "authPriv"),
        snmp_v3_auth_protocol=env_str("SNMP_V3_AUTH_PROTOCOL", "SHA"),
        snmp_v3_auth_password=env_str("SNMP_V3_AUTH_PASSWORD"),
        snmp_v3_priv_protocol=env_str("SNMP_V3_PRIV_PROTOCOL", "AES"),
        snmp_v3_priv_password=env_str("SNMP_V3_PRIV_PASSWORD"),
    )

    netbox = NetBoxSettings(
        url=env_str("NETBOX_URL", "http://netbox:8080").rstrip("/"),
        token=env_str("NETBOX_TOKEN"),
        verify_ssl=env_bool("NETBOX_VERIFY_SSL", False),
        site_name=env_str("NETBOX_SITE", "Main Site"),
        client_name=env_str("CLIENT_NAME", "Client"),
        default_prefix_len=env_int("DEFAULT_PREFIX_LEN", 24),
    )
    if not netbox.token:
        raise ConfigError("NETBOX_TOKEN is not set")

    lifecycle = LifecycleSettings(
        offline_after_hours=env_int("OFFLINE_AFTER_HOURS", 48),
        delete_after_days=env_int("DELETE_AFTER_DAYS", 7),
        enable_auto_delete=env_bool("ENABLE_AUTO_DELETE", True),
        protected_tag=env_str("PROTECTED_TAG", "protected"),
    )

    credentials, seeds = _load_inventory()

    # Implicit profiles built from .env, so a minimal deployment needs no YAML
    # at all. A profile of the same name in inventory.yml wins.
    credentials.setdefault(
        "default",
        {
            "type": "snmp",
            "snmp_version": scanner.snmp_default_version,
            "community": scanner.snmp_community,
            "v3_username": scanner.snmp_v3_username,
            "v3_security_level": scanner.snmp_v3_security_level,
            "v3_auth_protocol": scanner.snmp_v3_auth_protocol,
            "v3_auth_password": scanner.snmp_v3_auth_password,
            "v3_priv_protocol": scanner.snmp_v3_priv_protocol,
            "v3_priv_password": scanner.snmp_v3_priv_password,
        },
    )
    credentials.setdefault(
        "fortigate-default",
        {
            "type": "fortios",
            "api_token": env_str("FORTIGATE_API_TOKEN"),
            "port": env_int("FORTIGATE_PORT", 443),
            "vdom": env_str("FORTIGATE_VDOM", "root"),
            "verify_ssl": env_bool("FORTIGATE_VERIFY_SSL", False),
            "timeout": env_int("FORTIGATE_TIMEOUT", 20),
        },
    )

    # Single-switch shortcut from .env, so a deployment can be driven entirely
    # from environment variables without editing any YAML.
    if env_str("SWITCH_HOST") and not any(seed.method == "snmp" for seed in seeds):
        seeds.append(
            SeedEntry(
                name=env_str("SWITCH_NAME", "switch-01"),
                host=env_str("SWITCH_HOST"),
                method="snmp",
                credential="default",
                vendor=env_str("SWITCH_VENDOR"),
            )
        )

    # Single-FortiGate shortcut from .env: seeds one device on the first run.
    if env_str("FORTIGATE_HOST") and not any(
        seed.method == "fortios" for seed in seeds
    ):
        seeds.append(
            SeedEntry(
                name=env_str("FORTIGATE_NAME", "fortigate-01"),
                host=env_str("FORTIGATE_HOST"),
                method="fortios",
                credential="fortigate-default",
            )
        )

    api = ApiSettings(
        enabled=env_bool("API_ENABLED", True),
        # 0.0.0.0 because the container has no other useful interface; expose
        # the port deliberately in compose, and put TLS in front of it if it
        # leaves the management network.
        host=env_str("API_HOST", "0.0.0.0"),
        port=env_int("API_PORT", 8080),
    )

    return AppConfig(
        netbox=netbox,
        lifecycle=lifecycle,
        scanner=scanner,
        api=api,
        credentials=credentials,
        seeds=seeds,
    )


def load_raw_credentials() -> dict[str, dict]:
    """The `credentials` block of inventory.yml exactly as written.

    Unexpanded on purpose: importing a profile into the store needs to know
    that a value is `${SNMP_COMMUNITY}` rather than what that expands to, so it
    can be stored as a reference instead of a copy of the secret.
    """
    path = Path(env_str("INVENTORY_FILE", "/app/inventory.yml"))
    if not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    except yaml.YAMLError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(name).strip(): profile
        for name, profile in (raw.get("credentials") or {}).items()
        if isinstance(profile, dict)
    }


def _load_inventory() -> tuple[dict[str, dict], list[SeedEntry]]:
    path = Path(env_str("INVENTORY_FILE", "/app/inventory.yml"))
    if not path.is_file():
        return {}, []

    # A typo in this file must not take the appliance down with a traceback:
    # report where it is and let main() exit cleanly.
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise ConfigError(f"{path} is not valid YAML{where}: {problem}") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")

    raw = _expand(raw)

    credentials: dict[str, dict] = {}
    for name, profile in (raw.get("credentials") or {}).items():
        if not isinstance(profile, dict):
            raise ConfigError(f"credential profile '{name}' must be a mapping")
        credentials[str(name).strip()] = {
            key: value for key, value in profile.items() if value not in (None, "")
        }

    seeds: list[SeedEntry] = []
    seed_block = raw.get("seed") or {}
    if not isinstance(seed_block, dict):
        raise ConfigError("'seed' must be a mapping with 'switches' / 'fortigates'")

    # Pre-0.2 files listed the devices at the top level. Still accepted: they
    # simply become the seed, which is what they were being used for anyway.
    switch_items = (seed_block.get("switches") or []) + (raw.get("switches") or [])
    forti_items = (seed_block.get("fortigates") or []) + (raw.get("fortigates") or [])

    for item in switch_items:
        if isinstance(item, dict) and item.get("host"):
            seeds.append(_seed_from_dict(item, "snmp", "default"))
    for item in forti_items:
        if isinstance(item, dict) and item.get("host"):
            seeds.append(_seed_from_dict(item, "fortios", "fortigate-default"))

    return credentials, seeds


def _seed_from_dict(raw: dict, method: str, default_credential: str) -> SeedEntry:
    port = raw.get("port")
    return SeedEntry(
        name=str(raw.get("name") or raw["host"]).strip(),
        host=str(raw["host"]).strip(),
        method=method,
        credential=str(raw.get("credential") or default_credential).strip(),
        vendor=str(raw.get("vendor") or "").strip().lower(),
        port=int(port) if port else None,
    )
