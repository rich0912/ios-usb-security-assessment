#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
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

    result["configuration_profiles_count"] = len(cfg)
    result["provisioning_profiles_count"] = len(prov)
    result["has_configuration_profiles"] = len(cfg) > 0
    result["has_provisioning_profiles"] = len(prov) > 0
    return result


# ============================================================
# App 清單（ideviceinstaller）
# ============================================================

def ideviceinstaller_available() -> bool:
    return shutil.which("ideviceinstaller") is not None


def list_user_apps(udid: str) -> tuple[list[str], str | None]:
    if not ideviceinstaller_available():
        return [], "ideviceinstaller 未安裝"

    rc, out, err = run(
        ["ideviceinstaller", "-u", udid, "list", "--user"],
        timeout=90
    )
    if rc != 0:
        return [], err or out
    return [x for x in out.splitlines() if x.strip()], None


def extract_bundle_ids(lines: list[str]) -> list[str]:
    bundles = []
    for l in lines:
        if "CFBundleIdentifier:" in l:
            bundles.append(l.split("CFBundleIdentifier:", 1)[1].strip())
        else:
            bundles.append(l)
    return list(dict.fromkeys(bundles))


# ============================================================
# App 分類規則（核心）
# ============================================================

# ① 具備定位能力的 App（推定）
DEFAULT_LOCATION_KEYWORDS = [
    "maps", "waze", "uber", "lyft", "grab",
    "foodpanda", "ubereats", "doordash",
    "gogoro", "lime", "bird", "findmy",
]

# ② 同帳號可於多部裝置同時登入使用的 App（推定）
DEFAULT_MULTI_DEVICE_LOGIN_KEYWORDS = [
    "telegram", "whatsapp", "wechat", "line",
    "slack", "teams", "discord",
    "gmail", "outlook",
    "facebook", "instagram", "twitter", "x",
    "dropbox", "onedrive", "google", "drive",
]

# ③ VPN App（作為 VPN 存在的實務判斷依據）
DEFAULT_VPN_APP_KEYWORDS = [
    "wireguard", "openvpn", "nordvpn", "expressvpn",
    "protonvpn", "surfshark", "mullvad",
]

def classify_apps(bundle_ids: list[str], profiles: dict | None) -> dict:
    """
    App 分類結果（全部為『能力/特性推定』，非即時狀態）
    """
    location = []
    multi_device = []
    vpn_apps = []

    for b in bundle_ids:
        bl = b.lower()
        if any(k in bl for k in DEFAULT_LOCATION_KEYWORDS):
            location.append(b)
        if any(k in bl for k in DEFAULT_MULTI_DEVICE_LOGIN_KEYWORDS):
            multi_device.append(b)
        if any(k in bl for k in DEFAULT_VPN_APP_KEYWORDS):
            vpn_apps.append(b)

    return {
        "_comment": "App 能力分類（依應用程式設計行為模型推定，非即時狀態）",

        "location_capable_apps": {
            "_comment": "具備定位功能或高度可能使用定位服務的 App（不代表目前是否啟用定位）",
            "items": sorted(set(location))
        },

        "multi_device_login_capable_apps": {
            "_comment": "依服務設計，通常允許同一帳號於多部裝置同時登入使用的 App",
            "items": sorted(set(multi_device))
        },

        "non_app_store_suspected_apps": {
            "_comment": "疑似非 App Store 安裝的 App（僅能透過人工標記或 MDM 驗證；USB 工具無法直接判定）",
            "items": []
        },

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

def build_vpn_presence(classification: dict) -> dict:
    vpn_items = classification["vpn_apps_detected"]["items"]
    return {
        "_comment": "VPN 存在性判斷（以 VPN App 安裝為依據）",
        "present": bool(vpn_items),
        "evidence": ["vpn_app_installed"] if vpn_items else [],
        "apps": vpn_items,
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
    parser = argparse.ArgumentParser(description="iOS USB 掃描工具（App 能力分類 + VPN 判斷）")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--out", default="./reports")
    args = parser.parse_args()

    require_tool("idevice_id", "brew install libimobiledevice")
    require_tool("ideviceinfo", "brew install libimobiledevice")

    udids = detect_udids()
    ensure_dir(args.out)

    for udid in udids:
        info = collect_device_info(udid)
        profiles = cfgutil_get_profiles_summary(udid) if cfgutil_available() else None

        lines, _ = list_user_apps(udid)
        bundles = extract_bundle_ids(lines)
        classification = classify_apps(bundles, profiles)
        vpn = build_vpn_presence(classification)

        report = make_report("connected", udid, info, profiles, classification, vpn)
        path = os.path.join(args.out, f"{udid[:8]}_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print_event(f"[OK] {udid[:8]} -> {path}")


if __name__ == "__main__":
    main()