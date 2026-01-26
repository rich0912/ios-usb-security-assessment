#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ============================================================
# 工具與共用函式
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=timeout)
        return p.returncode, (out or "").strip(), (err or "").strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout running: {' '.join(cmd)}"


def require_tool(name: str, install_hint: str):
    if not shutil.which(name):
        print(f"[FATAL] 找不到 {name}。{install_hint}", file=sys.stderr)
        sys.exit(1)


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def print_event(msg: str):
    print(msg, flush=True)


def print_status(udid: str | None, msg: str):
    prefix = f"[{udid[:8]}]" if udid else "[INFO]"
    print_event(f"{prefix} {msg}")


def normalize_bundle_id(bundle_id: str) -> str:
    return bundle_id.strip().lower()


_BIDI_CONTROL_CHARS = {
    "\u061c",  # Arabic Letter Mark
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u202a",  # Left-to-Right Embedding
    "\u202b",  # Right-to-Left Embedding
    "\u202c",  # Pop Directional Formatting
    "\u202d",  # Left-to-Right Override
    "\u202e",  # Right-to-Left Override
    "\u2066",  # Left-to-Right Isolate
    "\u2067",  # Right-to-Left Isolate
    "\u2068",  # First Strong Isolate
    "\u2069",  # Pop Directional Isolate
    "\ufeff",  # Byte Order Mark
}


def strip_bidi_controls(text: str | None) -> str | None:
    if text is None:
        return None
    return "".join(ch for ch in text if ch not in _BIDI_CONTROL_CHARS)


def normalize_apps_list(apps: list[dict]) -> list[dict]:
    normalized = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        normalized.append(
            {
                "bundle_id": bundle_id,
                "display_name": strip_bidi_controls(app.get("display_name")),
                "version": app.get("version"),
            }
        )
    return sorted(normalized, key=lambda item: normalize_bundle_id(item["bundle_id"]))


def load_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_file(path: str, data: dict):
    dir_path = os.path.dirname(path)
    if dir_path:
        ensure_dir(dir_path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_bundle_overrides(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {"location": {}, "location_exclude": set(), "vpn": set()}
    try:
        data = load_json_file(path)
    except Exception as exc:
        print(f"[WARN] Failed to load bundle overrides: {exc}", file=sys.stderr, flush=True)
        return {"location": {}, "location_exclude": set(), "vpn": set()}

    location = {}
    location_exclude = set()
    location_raw = data.get("location") if isinstance(data, dict) else {}
    if isinstance(location_raw, dict):
        for bundle_id, rule in location_raw.items():
            if not isinstance(bundle_id, str):
                continue
            feature_id = None
            confidence = None
            if isinstance(rule, str):
                feature_id = rule
            elif isinstance(rule, dict):
                feature_id = rule.get("feature_id")
                confidence = rule.get("confidence")
            if feature_id:
                location[normalize_bundle_id(bundle_id)] = {
                    "feature_id": feature_id,
                    "confidence": confidence,
                }

    location_exclude_raw = data.get("location_exclude") if isinstance(data, dict) else []
    if isinstance(location_exclude_raw, list):
        for bundle_id in location_exclude_raw:
            if isinstance(bundle_id, str):
                location_exclude.add(normalize_bundle_id(bundle_id))
    elif isinstance(location_exclude_raw, dict):
        for bundle_id in location_exclude_raw.keys():
            if isinstance(bundle_id, str):
                location_exclude.add(normalize_bundle_id(bundle_id))

    vpn = set()
    vpn_raw = data.get("vpn") if isinstance(data, dict) else []
    if isinstance(vpn_raw, list):
        for bundle_id in vpn_raw:
            if isinstance(bundle_id, str):
                vpn.add(normalize_bundle_id(bundle_id))
    elif isinstance(vpn_raw, dict):
        for bundle_id in vpn_raw.keys():
            if isinstance(bundle_id, str):
                vpn.add(normalize_bundle_id(bundle_id))

    return {"location": location, "location_exclude": location_exclude, "vpn": vpn}


APP_RULES_EMPTY = {
    "location_features": [],
    "app_store_category_rules": [],
    "app_store_countries": [],
    "multi_device_login_keywords": [],
    "vpn_keywords": [],
    "payment_keywords": [],
}

ALLOWED_CONFIDENCE = {"low", "medium", "high"}


def normalize_country_list(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [x.strip() for x in raw.split(",")]
    if not isinstance(raw, list):
        return []
    countries = []
    for item in raw:
        if not isinstance(item, str):
            continue
        code = item.strip().lower()
        if code:
            countries.append(code)
    return list(dict.fromkeys(countries))


def load_app_rules(path: str) -> dict:
    if not path or not os.path.exists(path):
        print(f"[WARN] App rules not found: {path}", file=sys.stderr, flush=True)
        return dict(APP_RULES_EMPTY)
    try:
        data = load_json_file(path)
    except Exception as exc:
        print(f"[WARN] Failed to load app rules: {exc}", file=sys.stderr, flush=True)
        return dict(APP_RULES_EMPTY)
    if not isinstance(data, dict):
        print("[WARN] App rules JSON must be an object.", file=sys.stderr, flush=True)
        return dict(APP_RULES_EMPTY)

    def clean_keywords(raw) -> list[str]:
        if not isinstance(raw, list):
            return []
        cleaned = []
        for item in raw:
            if not isinstance(item, str):
                continue
            text = item.strip()
            if text:
                cleaned.append(text)
        return cleaned

    location_features = []
    for raw in data.get("location_features", []):
        if not isinstance(raw, dict):
            continue
        feature_id = raw.get("id")
        label = raw.get("label")
        if not feature_id or not label:
            continue
        confidence = raw.get("confidence") if raw.get("confidence") in ALLOWED_CONFIDENCE else "low"
        keywords = clean_keywords(raw.get("keywords"))
        location_features.append(
            {
                "id": feature_id,
                "label": label,
                "confidence": confidence,
                "keywords": keywords,
            }
        )

    app_store_category_rules = []
    for raw in data.get("app_store_category_rules", []):
        if not isinstance(raw, dict):
            continue
        genre = raw.get("genre")
        feature_id = raw.get("feature_id")
        if not genre or not feature_id:
            continue
        confidence = raw.get("confidence") if raw.get("confidence") in ALLOWED_CONFIDENCE else "low"
        requires_signal = bool(raw.get("requires_signal"))
        app_store_category_rules.append(
            {
                "genre": genre,
                "feature_id": feature_id,
                "confidence": confidence,
                "requires_signal": requires_signal,
            }
        )

    multi_device_keywords = [k.lower() for k in clean_keywords(data.get("multi_device_login_keywords"))]
    vpn_keywords = [k.lower() for k in clean_keywords(data.get("vpn_keywords"))]
    payment_keywords = [k.lower() for k in clean_keywords(data.get("payment_keywords"))]
    app_store_countries = normalize_country_list(data.get("app_store_countries"))

    return {
        "location_features": location_features,
        "app_store_category_rules": app_store_category_rules,
        "app_store_countries": app_store_countries,
        "multi_device_login_keywords": multi_device_keywords,
        "vpn_keywords": vpn_keywords,
        "payment_keywords": payment_keywords,
    }


def app_list_error_info(
    apps_error: str | None,
    profiles: dict | None = None,
) -> tuple[str | None, str | None, str | None]:
    if not apps_error:
        return None, None, None
    err = apps_error.lower()
    if "mc protected" in err:
        detail = "MDM policy blocks USB app enumeration (lockdownd: MC protected)."
        if isinstance(profiles, dict) and profiles.get("has_mdm_payloads"):
            detail += " MDM payloads detected."
        return "MC_PROTECTED", "MDM", detail
    if "not paired" in err or "pair" in err:
        return "NOT_PAIRED", "PAIRING", "Device is not paired or pairing was denied."
    if "timeout" in err:
        return "TIMEOUT", "USB", "USB communication timed out."
    return "UNKNOWN", None, "Unknown error."


def load_app_store_cache(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        data = load_json_file(path)
    except Exception as exc:
        print(f"[WARN] Failed to load App Store cache: {exc}", file=sys.stderr, flush=True)
        return {}
    return data if isinstance(data, dict) else {}


def save_app_store_cache(path: str, cache: dict):
    if not path:
        return
    save_json_file(path, cache)


def fetch_app_store_metadata(bundle_id: str, country: str, timeout: int = 8) -> dict:
    url = (
        "https://itunes.apple.com/lookup?bundleId="
        + urllib.parse.quote(bundle_id)
        + "&country="
        + urllib.parse.quote(country)
    )
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ios-usb-audit/1.0"},
    )
    result = {
        "bundle_id": bundle_id,
        "found": False,
        "checked_at": utc_now_iso(),
        "country": country,
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
        if isinstance(payload, dict) and payload.get("resultCount"):
            items = payload.get("results") or []
            if items:
                item = items[0]
                result.update(
                    {
                        "found": True,
                        "track_name": item.get("trackName"),
                        "primary_genre": item.get("primaryGenreName"),
                        "genres": item.get("genres") or [],
                        "seller_name": item.get("sellerName"),
                    }
                )
    except Exception as exc:
        result["error"] = str(exc)
    return result


def app_store_cache_key(bundle_id: str, countries: list[str]) -> str:
    return f"{normalize_bundle_id(bundle_id)}|{','.join(countries)}"


def collect_app_store_metadata(
    apps: list[dict],
    cache: dict,
    countries: list[str],
    timeout: int = 8,
    max_requests: int = 0,
) -> dict:
    results = {}
    looked_up = 0
    countries = normalize_country_list(countries)
    if not countries:
        countries = ["us"]
    for app in apps:
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        cache_key = app_store_cache_key(bundle_id, countries)
        if cache_key in cache:
            results[normalize_bundle_id(bundle_id)] = cache[cache_key]
            continue
        if max_requests and looked_up >= max_requests:
            continue
        meta = {
            "bundle_id": bundle_id,
            "found": False,
            "checked_at": utc_now_iso(),
            "countries_tried": [],
        }
        errors = []
        for country in countries:
            if max_requests and looked_up >= max_requests:
                meta["partial"] = True
                break
            resp = fetch_app_store_metadata(bundle_id, country, timeout=timeout)
            looked_up += 1
            meta["countries_tried"].append(country)
            if resp.get("error"):
                errors.append(resp.get("error"))
                continue
            if resp.get("found"):
                meta.update(resp)
                meta["found"] = True
                meta["country"] = country
                break
        if errors:
            meta["errors"] = errors
        if not meta.get("found") and not errors and not meta.get("partial"):
            meta["not_found"] = True
        cache[cache_key] = meta
        results[normalize_bundle_id(bundle_id)] = meta
    return results


# ============================================================
# iOS 裝置偵測（libimobiledevice）
# ============================================================

def detect_udids() -> list[str]:
    rc, out, err = run(["idevice_id", "-l"], timeout=10)
    if rc != 0:
        raise RuntimeError(err or out or "idevice_id failed")
    return sorted([x for x in out.splitlines() if x.strip()])


def ideviceinfo_k(udid: str, key: str) -> str | None:
    rc, out, _ = run(["ideviceinfo", "-u", udid, "-k", key], timeout=10)
    return out if rc == 0 and out else None


def collect_device_info(udid: str) -> dict:
    keys = [
        "DeviceName", "ProductType", "ProductVersion", "BuildVersion",
        "SerialNumber", "UniqueDeviceID", "UniqueChipID",
        "HardwareModel", "ModelNumber", "DeviceClass",
    ]
    info = {k: ideviceinfo_k(udid, k) for k in keys}
    info["UDID"] = udid
    return info


# ============================================================
# cfgutil：描述檔 / provisioning profile 訊號（裝置層）
# ============================================================

def cfgutil_available() -> bool:
    return shutil.which("cfgutil") is not None


VPN_PAYLOAD_TYPE_CONFIDENCE = {
    "com.apple.vpn.managed": "high",
    "com.apple.vpn.managed.applayer": "high",
    "com.apple.networkextension": "medium",
}

MDM_PAYLOAD_TYPE_CONFIDENCE = {
    "com.apple.mdm": "high",
}


def find_payload_dicts(obj):
    found = []
    if isinstance(obj, dict):
        if "PayloadType" in obj and isinstance(obj.get("PayloadType"), str):
            found.append(obj)
        for v in obj.values():
            found.extend(find_payload_dicts(v))
    elif isinstance(obj, list):
        for i in obj:
            found.extend(find_payload_dicts(i))
    return found


def extract_vpn_payloads(parsed: dict) -> list[dict]:
    payloads = []
    seen = set()
    for payload in find_payload_dicts(parsed):
        payload_type = payload.get("PayloadType")
        if payload_type not in VPN_PAYLOAD_TYPE_CONFIDENCE:
            continue
        key = (
            payload_type,
            payload.get("PayloadIdentifier"),
            payload.get("PayloadUUID"),
        )
        if key in seen:
            continue
        seen.add(key)
        payloads.append(
            {
                "payload_type": payload_type,
                "payload_identifier": payload.get("PayloadIdentifier"),
                "payload_display_name": payload.get("PayloadDisplayName"),
                "payload_uuid": payload.get("PayloadUUID"),
                "confidence": VPN_PAYLOAD_TYPE_CONFIDENCE.get(payload_type),
            }
        )
    return payloads


def extract_configuration_profiles(profiles: list) -> list[dict]:
    summaries = []
    seen = set()

    def pick_value(profile: dict, *keys):
        for key in keys:
            value = profile.get(key)
            if value not in (None, ""):
                return value
        return None

    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        summary = {}
        display_name = pick_value(
            profile,
            "PayloadDisplayName",
            "ProfileDisplayName",
            "ProfileName",
            "displayName",
            "name",
        )
        identifier = pick_value(
            profile,
            "PayloadIdentifier",
            "ProfileIdentifier",
            "identifier",
        )
        uuid = pick_value(profile, "PayloadUUID", "ProfileUUID", "uuid")
        organization = pick_value(
            profile,
            "PayloadOrganization",
            "ProfileOrganization",
            "organization",
        )
        description = pick_value(
            profile,
            "PayloadDescription",
            "ProfileDescription",
            "description",
        )
        payload_type = pick_value(profile, "PayloadType", "payloadType")
        payload_scope = pick_value(profile, "PayloadScope", "payloadScope")
        payload_version = pick_value(profile, "PayloadVersion", "payloadVersion", "version")
        removal_disallowed = pick_value(
            profile,
            "PayloadRemovalDisallowed",
            "ProfileRemovalDisallowed",
            "removalDisallowed",
        )
        has_removal_password = pick_value(profile, "HasRemovalPassword", "hasRemovalPassword")
        install_date = pick_value(
            profile,
            "ProfileInstallDate",
            "ProfileInstallDateUTC",
            "InstallDate",
            "installDate",
        )

        if display_name is not None:
            summary["display_name"] = display_name
        if identifier is not None:
            summary["identifier"] = identifier
        if uuid is not None:
            summary["uuid"] = uuid
        if organization is not None:
            summary["organization"] = organization
        if description is not None:
            summary["description"] = description
        if payload_type is not None:
            summary["payload_type"] = payload_type
        if payload_scope is not None:
            summary["payload_scope"] = payload_scope
        if payload_version is not None:
            summary["version"] = payload_version
        if removal_disallowed is not None:
            summary["removal_disallowed"] = removal_disallowed
        if has_removal_password is not None:
            summary["has_removal_password"] = has_removal_password
        if install_date is not None:
            summary["install_date"] = install_date

        if not summary:
            continue
        key = (summary.get("identifier"), summary.get("uuid"), summary.get("display_name"))
        if key in seen:
            continue
        seen.add(key)
        summaries.append(summary)
    return summaries


def extract_mdm_payloads(parsed: dict) -> list[dict]:
    payloads = []
    seen = set()
    for payload in find_payload_dicts(parsed):
        payload_type = payload.get("PayloadType")
        if payload_type not in MDM_PAYLOAD_TYPE_CONFIDENCE:
            continue
        key = (
            payload_type,
            payload.get("PayloadIdentifier"),
            payload.get("PayloadUUID"),
        )
        if key in seen:
            continue
        seen.add(key)
        payloads.append(
            {
                "payload_type": payload_type,
                "payload_identifier": payload.get("PayloadIdentifier"),
                "payload_display_name": payload.get("PayloadDisplayName"),
                "payload_uuid": payload.get("PayloadUUID"),
                "confidence": MDM_PAYLOAD_TYPE_CONFIDENCE.get(payload_type),
            }
        )
    return payloads


def cfgutil_get_profiles_summary(udid: str) -> dict:
    """
    只做「裝置層級」的摘要，不解析內容。
    用途：
    - 判斷是否存在描述檔 / provisioning profile
    - 作為「非 App Store 安裝」的弱訊號
    """
    result = {
        "_comment": "描述檔與佈署設定摘要（裝置層級）",
        "available": True,
        "error": None,
        "configuration_profiles_count": None,
        "provisioning_profiles_count": None,
        "has_configuration_profiles": None,
        "has_provisioning_profiles": None,
        "vpn_payloads_count": None,
        "has_vpn_payloads": None,
        "vpn_payloads": None,
        "mdm_payloads_count": None,
        "has_mdm_payloads": None,
        "mdm_payloads": None,
    }

    ecid = ideviceinfo_k(udid, "UniqueChipID")
    if not ecid:
        result["error"] = "無法取得 ECID"
        return result

    rc, out, err = run(
        ["cfgutil", "-e", ecid, "--format", "JSON", "get", "all"],
        timeout=60
    )
    if rc != 0 or not out:
        result["error"] = err or out
        return result

    try:
        parsed = json.loads(out)
    except Exception:
        result["error"] = "cfgutil 回傳非 JSON"
        return result

    def find_lists(obj, name):
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == name and isinstance(v, list):
                    found.extend(v)
                else:
                    found.extend(find_lists(v, name))
        elif isinstance(obj, list):
            for i in obj:
                found.extend(find_lists(i, name))
        return found

    cfg = find_lists(parsed, "configurationProfiles")
    prov = find_lists(parsed, "provisioningProfiles")
    cfg_profiles = extract_configuration_profiles(cfg)
    vpn_payloads = extract_vpn_payloads(parsed)
    mdm_payloads = extract_mdm_payloads(parsed)

    result["configuration_profiles_count"] = len(cfg_profiles) if cfg_profiles else len(cfg)
    result["provisioning_profiles_count"] = len(prov)
    result["has_configuration_profiles"] = result["configuration_profiles_count"] > 0
    result["has_provisioning_profiles"] = len(prov) > 0
    result["configuration_profiles"] = cfg_profiles
    result["vpn_payloads_count"] = len(vpn_payloads)
    result["has_vpn_payloads"] = len(vpn_payloads) > 0
    result["vpn_payloads"] = vpn_payloads
    result["mdm_payloads_count"] = len(mdm_payloads)
    result["has_mdm_payloads"] = len(mdm_payloads) > 0
    result["mdm_payloads"] = mdm_payloads
    return result


# ============================================================
# App 清單（ideviceinstaller）
# ============================================================

def ideviceinstaller_available() -> bool:
    return shutil.which("ideviceinstaller") is not None


def list_user_apps(udid: str) -> tuple[list[dict], str | None]:
    if not ideviceinstaller_available():
        return [], "ideviceinstaller 未安裝"

    rc, out, err = run(
        ["ideviceinstaller", "-u", udid, "list", "--user"],
        timeout=90
    )
    if rc != 0:
        return [], err or out
    return parse_app_list(out), None


def parse_app_list(out: str) -> list[dict]:
    lines = [x for x in out.splitlines() if x.strip()]
    if not lines:
        return []
    if lines[0].startswith("CFBundleIdentifier"):
        return parse_app_list_csv(out)
    return parse_app_list_plain(lines)


def _clean_csv_field(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] == '"':
        cleaned = cleaned[1:-1]
    return cleaned or None


def parse_app_list_csv(out: str) -> list[dict]:
    apps = []
    reader = csv.reader(io.StringIO(out), skipinitialspace=True)
    for idx, row in enumerate(reader):
        if not row:
            continue
        if idx == 0 and row[0].strip() == "CFBundleIdentifier":
            continue
        bundle_id = _clean_csv_field(row[0]) if len(row) > 0 else ""
        if not bundle_id:
            continue
        version = _clean_csv_field(row[1]) if len(row) > 1 else None
        name = _clean_csv_field(row[2]) if len(row) > 2 else None
        apps.append(
            {
                "bundle_id": bundle_id,
                "version": version or None,
                "display_name": name or None,
            }
        )
    return apps


def parse_app_list_plain(lines: list[str]) -> list[dict]:
    apps = []
    for line in lines:
        bundle_id = line.strip()
        name = None
        if " - " in line:
            bundle_id, name = line.split(" - ", 1)
            bundle_id = bundle_id.strip()
            name = name.strip() or None
        elif "CFBundleIdentifier:" in line:
            bundle_id = line.split("CFBundleIdentifier:", 1)[1].strip()
        if bundle_id:
            apps.append(
                {
                    "bundle_id": bundle_id,
                    "version": None,
                    "display_name": name,
                }
            )
    return apps


def app_haystack(app: dict) -> str:
    parts = [
        app.get("bundle_id"),
        app.get("display_name"),
    ]
    return " ".join([p for p in parts if p]).lower()


def normalize_keywords(values: list[str]) -> list[str]:
    keywords = []
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip().lower()
        if cleaned:
            keywords.append(cleaned)
    return sorted(set(keywords))


# ============================================================
# App 分類規則（核心）
# ============================================================

LOCATION_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
LOCATION_CONFIDENCE_LABEL = {1: "low", 2: "medium", 3: "high"}

def analyze_location_apps(
    apps: list[dict],
    location_features: list[dict],
    app_store_category_rules: list[dict],
    location_overrides: dict | None = None,
    location_exclude: set[str] | None = None,
    app_store_data: dict | None = None,
) -> tuple[list[str], dict, dict, dict]:
    matched_apps = set()
    evidence = {}
    features = {}
    summary = {"high": 0, "medium": 0, "low": 0}
    feature_by_id = {rule["id"]: rule for rule in location_features}
    app_store_rules = {
        rule["genre"].lower(): rule for rule in app_store_category_rules if isinstance(rule.get("genre"), str)
    }
    location_overrides = location_overrides or {}
    location_exclude = location_exclude or set()
    app_store_data = app_store_data or {}

    for app in apps:
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        bundle_key = normalize_bundle_id(bundle_id)
        if bundle_key in location_exclude:
            continue
        haystack = app_haystack(app)
        app_matches = []
        app_conf_rank = 0

        def add_match(
            feature_id: str,
            label: str,
            confidence: str,
            source: str,
            keywords: list[str] | None = None,
            genre: str | None = None,
        ):
            nonlocal app_conf_rank
            matched_apps.add(bundle_id)
            match = {
                "feature_id": feature_id,
                "feature_label": label,
                "confidence": confidence,
                "source": source,
            }
            if keywords:
                match["keywords"] = keywords
            if genre:
                match["genre"] = genre
            app_matches.append(match)
            feature = features.setdefault(
                feature_id,
                {
                    "label": label,
                    "confidence_rank": 0,
                    "apps": [],
                },
            )
            feature["apps"].append(bundle_id)
            rank = LOCATION_CONFIDENCE_RANK.get(confidence, 1)
            feature["confidence_rank"] = max(feature["confidence_rank"], rank)
            app_conf_rank = max(app_conf_rank, rank)

        override = location_overrides.get(bundle_key)
        if override:
            feature_id = override.get("feature_id") if isinstance(override, dict) else None
            rule = feature_by_id.get(feature_id) if feature_id else None
            if rule:
                confidence = override.get("confidence") or rule["confidence"]
                add_match(
                    feature_id,
                    rule["label"],
                    confidence,
                    "bundle_id_rule",
                )

        for rule in location_features:
            if not rule.get("keywords"):
                continue
            matched_keywords = [kw for kw in rule["keywords"] if kw.lower() in haystack]
            if not matched_keywords:
                continue
            add_match(
                rule["id"],
                rule["label"],
                rule["confidence"],
                "keyword",
                keywords=matched_keywords,
            )

        meta = app_store_data.get(bundle_key)
        if isinstance(meta, dict) and meta.get("found"):
            genres = []
            primary_genre = meta.get("primary_genre")
            if primary_genre:
                genres.append(primary_genre)
            for g in meta.get("genres") or []:
                if g:
                    genres.append(g)
            for genre in genres:
                rule = app_store_rules.get(genre.lower())
                if not rule:
                    continue
                if rule.get("requires_signal") and not app_matches:
                    continue
                feature_id = rule["feature_id"]
                feature = feature_by_id.get(feature_id)
                if not feature:
                    continue
                add_match(
                    feature_id,
                    feature["label"],
                    rule["confidence"],
                    "app_store_genre",
                    genre=genre,
                )

        if app_matches:
            confidence = LOCATION_CONFIDENCE_LABEL.get(app_conf_rank, "low")
            entry = {
                "display_name": app.get("display_name"),
                "version": app.get("version"),
                "confidence": confidence,
                "matches": app_matches,
            }
            if isinstance(meta, dict) and meta.get("found"):
                entry["app_store"] = {
                    "primary_genre": meta.get("primary_genre"),
                    "genres": meta.get("genres") or [],
                    "track_name": meta.get("track_name"),
                }
            evidence[bundle_id] = entry
            summary[confidence] = summary.get(confidence, 0) + 1

    for feature in features.values():
        feature["apps"] = sorted(set(feature["apps"]))
        rank = feature.pop("confidence_rank", 1)
        feature["confidence"] = LOCATION_CONFIDENCE_LABEL.get(rank, "low")

    return sorted(matched_apps), evidence, features, summary


def analyze_non_app_store_apps(apps: list[dict], app_store_data: dict) -> tuple[list[str], dict]:
    items = []
    evidence = {}
    for app in apps:
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        key = normalize_bundle_id(bundle_id)
        meta = app_store_data.get(key)
        if not isinstance(meta, dict):
            continue
        if meta.get("found"):
            continue
        if meta.get("errors") or meta.get("partial"):
            continue
        if not meta.get("not_found"):
            continue
        items.append(bundle_id)
        evidence[bundle_id] = {
            "app_store_found": False,
            "checked_at": meta.get("checked_at"),
            "countries_tried": meta.get("countries_tried") or [],
        }
    return sorted(set(items)), evidence


def analyze_payment_apps(apps: list[dict], payment_keywords: list[str]) -> tuple[list[str], dict]:
    items = []
    evidence = {}
    if not payment_keywords:
        return items, evidence
    for app in apps:
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        haystack = app_haystack(app)
        matched = [kw for kw in payment_keywords if kw in haystack]
        if not matched:
            continue
        items.append(bundle_id)
        evidence[bundle_id] = {
            "matched_keywords": matched,
            "display_name": app.get("display_name"),
        }
    return sorted(set(items)), evidence


def summarize_app_store_presence(apps: list[dict], app_store_data: dict) -> dict:
    summary = {
        "_comment": "App Store 查詢結果（依安裝 App）",
        "found": [],
        "not_found": [],
        "errors": [],
    }
    seen = set()
    for app in apps:
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        key = normalize_bundle_id(bundle_id)
        if key in seen:
            continue
        seen.add(key)
        meta = app_store_data.get(key)
        if not isinstance(meta, dict):
            continue
        entry = {"bundle_id": bundle_id}
        display_name = app.get("display_name")
        if display_name:
            entry["display_name"] = display_name
        if meta.get("found"):
            entry["country"] = meta.get("country")
            track_name = meta.get("track_name")
            if track_name:
                entry["track_name"] = track_name
            primary_genre = meta.get("primary_genre")
            if primary_genre:
                entry["primary_genre"] = primary_genre
            summary["found"].append(entry)
        elif meta.get("not_found"):
            entry["countries_tried"] = meta.get("countries_tried") or []
            summary["not_found"].append(entry)
        elif meta.get("errors") or meta.get("partial"):
            entry["countries_tried"] = meta.get("countries_tried") or []
            if meta.get("errors"):
                entry["errors"] = meta.get("errors")
            if meta.get("partial"):
                entry["partial"] = True
            summary["errors"].append(entry)
    for key in ("found", "not_found", "errors"):
        summary[key] = sorted(summary[key], key=lambda item: item.get("bundle_id") or "")
    return summary


def classify_apps(
    apps: list[dict],
    profiles: dict | None,
    apps_error: str | None = None,
    bundle_overrides: dict | None = None,
    app_store_data: dict | None = None,
    app_rules: dict | None = None,
) -> dict:
    """
    App 分類結果（全部為『能力/特性推定』，非即時狀態）
    """
    bundle_overrides = bundle_overrides or {}
    app_rules = app_rules or dict(APP_RULES_EMPTY)
    app_store_lookup_enabled = app_store_data is not None
    app_store_data = app_store_data or {}
    location_overrides = bundle_overrides.get("location") or {}
    location_exclude = bundle_overrides.get("location_exclude") or set()
    vpn_overrides = bundle_overrides.get("vpn") or set()
    location_feature_rules = app_rules.get("location_features") or []
    app_store_category_rules = app_rules.get("app_store_category_rules") or []
    multi_device_keywords = app_rules.get("multi_device_login_keywords") or []
    vpn_keywords = app_rules.get("vpn_keywords") or []
    payment_keywords = normalize_keywords(app_rules.get("payment_keywords") or [])
    location_items, location_evidence, location_features, location_summary = analyze_location_apps(
        apps,
        location_feature_rules,
        app_store_category_rules,
        location_overrides=location_overrides,
        location_exclude=location_exclude,
        app_store_data=app_store_data,
    )
    non_appstore_items = []
    non_appstore_evidence = {}
    app_store_lookup_summary = {}
    if app_store_lookup_enabled:
        non_appstore_items, non_appstore_evidence = analyze_non_app_store_apps(apps, app_store_data)
        app_store_lookup_summary = summarize_app_store_presence(apps, app_store_data)
    payment_items, payment_evidence = analyze_payment_apps(apps, payment_keywords)
    multi_device = []
    vpn_apps = []

    for app in apps:
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        bl = normalize_bundle_id(bundle_id)
        if any(k in bl for k in multi_device_keywords):
            multi_device.append(bundle_id)
        if any(k in bl for k in vpn_keywords):
            vpn_apps.append(bundle_id)
        if bl in vpn_overrides:
            vpn_apps.append(bundle_id)

    app_list_error_code, app_list_error_reason, app_list_error_detail = app_list_error_info(
        apps_error,
        profiles,
    )
    apps_list = normalize_apps_list(apps)

    return {
        "_comment": "App 能力分類（依應用程式設計行為模型推定，非即時狀態）",
        "apps_total_count": len(apps_list),
        "apps_list": apps_list,
        "app_list_complete": apps_error is None,
        "app_list_error": apps_error,
        "app_list_error_code": app_list_error_code,
        "app_list_error_reason": app_list_error_reason,
        "app_list_error_detail": app_list_error_detail,

        "location_capable_apps": {
            "_comment": "具備定位功能或高度可能使用定位服務的 App（不代表目前是否啟用定位）",
            "items": location_items,
            "evidence": location_evidence,
            "features": location_features,
            "summary": location_summary,
        },

        "multi_device_login_capable_apps": {
            "_comment": "依服務設計，通常允許同一帳號於多部裝置同時登入使用的 App",
            "items": sorted(set(multi_device))
        },

        "non_app_store_suspected_apps": {
            "_comment": (
                "疑似非 App Store 安裝的 App（App Store 查詢未找到即列入，"
                "仍需人工或 MDM 驗證）"
            ),
            "items": non_appstore_items,
            "evidence": non_appstore_evidence,
        },
        "payment_apps": {
            "_comment": "第三方支付工具（可能推定消費地點）",
            "items": payment_items,
            "evidence": payment_evidence,
        },
        "app_store_lookup_summary": app_store_lookup_summary,

        "vpn_apps_detected": {
            "_comment": "偵測到的 VPN App（作為裝置存在 VPN 能力的實務判斷依據）",
            "items": sorted(set(vpn_apps))
        },

        "device_non_appstore_signal": {
            "_comment": "裝置層級訊號：若存在 provisioning profile，可能代表曾安裝企業/測試 App",
            "value": (
                profiles.get("has_provisioning_profiles")
                if isinstance(profiles, dict) else None
            )
        }
    }


# ============================================================
# VPN 存在判斷（你指定：只要知道有沒有）
# ============================================================

def build_vpn_presence(classification: dict, profiles: dict | None) -> dict:
    vpn_items = classification["vpn_apps_detected"]["items"]
    profile_payloads = []
    profile_present = None
    if isinstance(profiles, dict):
        profile_payloads = profiles.get("vpn_payloads") or []
        profile_present = profiles.get("has_vpn_payloads")
    evidence = []
    if vpn_items:
        evidence.append("vpn_app_installed")
    if profile_present:
        evidence.append("vpn_profile_payload")
    return {
        "_comment": "VPN 存在性判斷（以 VPN App 安裝或設定檔 payload 為依據）",
        "present": bool(vpn_items) or bool(profile_present),
        "evidence": evidence,
        "apps": vpn_items,
        "profile_payloads": profile_payloads,
    }


# ============================================================
# 報告輸出
# ============================================================

def make_report(event, udid, device_info, profiles, apps, vpn):
    return {
        "timestamp": utc_now_iso(),
        "event": event,
        "udid": udid,
        "device_info": device_info,
        "profiles": profiles,
        "apps": apps,
        "vpn": vpn,
    }


# ============================================================
# Main
# ============================================================

def main():
    default_rules_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "rules", "app_bundle_overrides.json")
    )
    default_app_rules_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "rules", "app_rules.json")
    )
    parser = argparse.ArgumentParser(description="iOS USB 掃描工具（App 能力分類 + VPN 判斷）")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--out", default="./reports")
    parser.add_argument("--bundle-rules", default=default_rules_path, help="Bundle ID overrides JSON")
    parser.add_argument("--app-rules", default=default_app_rules_path, help="App rules JSON")
    parser.add_argument("--app-store", action="store_true", help="Enable App Store metadata lookup")
    parser.add_argument("--app-store-cache", default="./cache/app_store_cache.json", help="App Store cache file")
    parser.add_argument("--app-store-timeout", type=int, default=8, help="App Store request timeout (s)")
    parser.add_argument("--app-store-max", type=int, default=0, help="Max App Store requests (0 = no limit)")
    parser.add_argument("--app-store-country", default=None, help="App Store country code (e.g. tw)")
    parser.add_argument(
        "--app-store-countries",
        default=None,
        help="Comma-separated App Store country codes (overrides rules)",
    )
    args = parser.parse_args()

    require_tool("idevice_id", "brew install libimobiledevice")
    require_tool("ideviceinfo", "brew install libimobiledevice")

    print_status(None, "開始掃描 USB 裝置")
    udids = detect_udids()
    ensure_dir(args.out)
    bundle_overrides = load_bundle_overrides(args.bundle_rules)
    app_rules = load_app_rules(args.app_rules)
    app_store_countries = []
    if args.app_store_countries:
        app_store_countries = normalize_country_list(args.app_store_countries)
    elif args.app_store_country:
        app_store_countries = normalize_country_list([args.app_store_country])
    elif app_rules.get("app_store_countries"):
        app_store_countries = normalize_country_list(app_rules.get("app_store_countries"))
    app_store_cache = load_app_store_cache(args.app_store_cache) if args.app_store else {}

    if not udids:
        print_status(None, "未偵測到 iOS 裝置")
        return

    for udid in udids:
        print_status(udid, "讀取裝置資訊")
        info = collect_device_info(udid)
        if cfgutil_available():
            print_status(udid, "讀取描述檔/佈署設定摘要")
            profiles = cfgutil_get_profiles_summary(udid)
        else:
            print_status(udid, "cfgutil 未安裝，跳過描述檔/佈署設定摘要")
            profiles = None

        print_status(udid, "列出使用者安裝的 App")
        apps, apps_err = list_user_apps(udid)
        if apps_err:
            print(f"[WARN] {udid[:8]} app list unavailable: {apps_err}", file=sys.stderr, flush=True)
        app_store_data = {}
        if args.app_store and apps and not apps_err:
            print_status(udid, f"查詢 App Store metadata ({len(apps)} apps)")
            app_store_data = collect_app_store_metadata(
                apps,
                app_store_cache,
                app_store_countries,
                timeout=args.app_store_timeout,
                max_requests=args.app_store_max,
            )
        elif args.app_store and apps_err:
            print_status(udid, "App list error，跳過 App Store metadata 查詢")

        classification = classify_apps(
            apps,
            profiles,
            apps_err,
            bundle_overrides=bundle_overrides,
            app_store_data=app_store_data,
            app_rules=app_rules,
        )
        vpn = build_vpn_presence(classification, profiles)

        print_status(udid, "輸出報告")
        report = make_report("connected", udid, info, profiles, classification, vpn)
        path = os.path.join(args.out, f"{udid[:8]}_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print_event(f"[OK] {udid[:8]} -> {path}")

    if args.app_store:
        save_app_store_cache(args.app_store_cache, app_store_cache)


if __name__ == "__main__":
    main()
