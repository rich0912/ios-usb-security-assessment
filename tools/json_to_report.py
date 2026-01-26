#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import json
import os
from datetime import datetime


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_get(d: dict, path: list):
    cur = d
    for k in path:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return None
    return cur


def iso_now_local() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def coerce_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    # 兼容某些工具輸出可能是 dict 或 str
    return [str(x)]


def rating_for_list(items: list, empty_rating="PASS", nonempty_rating="INFO"):
    return empty_rating if len(items) == 0 else nonempty_rating


def rating_for_bool(flag: bool | None, false_rating="PASS", true_rating="INFO"):
    if flag is True:
        return true_rating
    return false_rating


def build_findings_for_device(device: dict) -> dict:
    """
    依你的 JSON schema 產出標準化 findings 結構：
    - 每一項包含：id/title/risk/status/evidence
    """
    device_info = device.get("device_info") or {}
    profiles = device.get("profiles") or {}
    apps = device.get("apps") or {}
    vpn = device.get("vpn") or {}

    apps_meta = apps if isinstance(apps, dict) else {}
    app_list_complete = apps_meta.get("app_list_complete")
    app_list_error = apps_meta.get("app_list_error")
    app_list_error_code = apps_meta.get("app_list_error_code")
    app_list_error_reason = apps_meta.get("app_list_error_reason")
    app_list_error_detail = apps_meta.get("app_list_error_detail")
    app_store_summary = apps_meta.get("app_store_lookup_summary")
    if not isinstance(app_store_summary, dict):
        app_store_summary = {}
    apps_list = apps_meta.get("apps_list")
    if not isinstance(apps_list, list):
        apps_list = []
    if isinstance(app_list_error, str) and "mc protected" in app_list_error.lower():
        app_list_error_code = app_list_error_code or "MC_PROTECTED"
        if not app_list_error_reason:
            app_list_error_reason = "MDM"
        if not app_list_error_detail:
            app_list_error_detail = "MDM policy blocks USB app enumeration (lockdownd: MC protected)."
    if app_list_complete is None:
        if app_list_error is None:
            app_list_complete = True if apps_meta else None
        else:
            app_list_complete = False

    # 兼容多種 apps 結構：
    # - apps.classification.<x>.items
    # - apps.classification.<x> 直接是 list (舊版)
    # - apps.<x>.items（新版工具直接輸出分類在 apps 下）
    cls = apps.get("classification")
    if not isinstance(cls, dict):
        cls = apps if isinstance(apps, dict) else {}

    def cls_items(key: str) -> list:
        v = cls.get(key)
        if isinstance(v, dict) and "items" in v:
            return coerce_list(v.get("items"))
        return coerce_list(v)

    location_block = cls.get("location_capable_apps")
    if isinstance(location_block, dict):
        location_apps = coerce_list(location_block.get("items"))
        location_evidence = location_block.get("evidence") or {}
        location_features = location_block.get("features") or {}
        location_summary = location_block.get("summary") or {}
    else:
        location_apps = coerce_list(location_block)
        location_evidence = {}
        location_features = {}
        location_summary = {}

    multi_device_apps = cls_items("multi_device_login_capable_apps")
    non_appstore_apps = cls_items("non_app_store_suspected_apps")
    payment_block = cls.get("payment_apps")
    if isinstance(payment_block, dict):
        payment_apps = coerce_list(payment_block.get("items"))
        payment_evidence = payment_block.get("evidence") or {}
    else:
        payment_apps = coerce_list(payment_block)
        payment_evidence = {}

    cfg_count = profiles.get("configuration_profiles_count")
    prov_count = profiles.get("provisioning_profiles_count")
    has_cfg = profiles.get("has_configuration_profiles")
    has_prov = profiles.get("has_provisioning_profiles")
    cfg_profiles = profiles.get("configuration_profiles")
    if not isinstance(cfg_profiles, list):
        cfg_profiles = []
    mdm_payloads = profiles.get("mdm_payloads")
    if not isinstance(mdm_payloads, list):
        mdm_payloads = []
    has_mdm_payloads = profiles.get("has_mdm_payloads")

    # 統一成 count 判定（若 count 缺失則用 bool）
    profiles_error = profiles.get("error") if isinstance(profiles, dict) else None
    profiles_checked = (
        isinstance(profiles, dict)
        and (
            "configuration_profiles_count" in profiles
            or "provisioning_profiles_count" in profiles
            or "available" in profiles
        )
        and not profiles_error
    )
    cfg_present = (cfg_count or 0) > 0 if cfg_count is not None else bool(has_cfg)
    prov_present = (prov_count or 0) > 0 if prov_count is not None else bool(has_prov)
    mdm_present = bool(has_mdm_payloads) or app_list_error_reason == "MDM"

    vpn_present = bool(vpn.get("present"))
    vpn_apps = coerce_list(vpn.get("apps"))
    vpn_profile_payloads = vpn.get("profile_payloads")
    if not isinstance(vpn_profile_payloads, list):
        vpn_profile_payloads = []

    apps_total_count = apps_meta.get("apps_total_count")
    if not isinstance(apps_total_count, int):
        apps_total_count = None
    store_found = app_store_summary.get("found") or []
    store_not_found = app_store_summary.get("not_found") or []
    store_errors = app_store_summary.get("errors") or []
    if apps_total_count is None:
        total_lookup = len(store_found) + len(store_not_found) + len(store_errors)
        if total_lookup:
            apps_total_count = total_lookup

    cfg_names = summarize_values(
        collect_labels(cfg_profiles, ["display_name", "identifier", "uuid"]),
        limit=5,
    )
    cfg_detail = f"count={cfg_count or 0}"
    if cfg_names:
        cfg_detail += f", names={cfg_names}"
    prov_detail = f"count={prov_count or 0}"
    mdm_names = summarize_values(
        collect_labels(mdm_payloads, ["payload_display_name", "payload_identifier", "payload_uuid"]),
        limit=5,
    )
    mdm_detail = f"count={len(mdm_payloads)}"
    if mdm_names:
        mdm_detail += f", names={mdm_names}"
    vpn_payload_names = summarize_values(
        collect_labels(vpn_profile_payloads, ["payload_display_name", "payload_identifier", "payload_uuid"]),
        limit=5,
    )
    vpn_payload_detail = f"count={len(vpn_profile_payloads)}"
    if vpn_payload_names:
        vpn_payload_detail += f", names={vpn_payload_names}"

    app_list_detail = f"count={apps_total_count if apps_total_count is not None else 'unknown'}"
    if app_list_complete is False:
        app_list_detail += ", app_list_complete=False"
    if app_list_error_code or app_list_error_reason:
        app_list_detail += f", app_list_error={app_list_error_code or app_list_error_reason}"

    findings = [
        {
            "id": "V-01",
            "title": "裝置基本資訊可被列舉",
            "risk": "Low",
            "status": "INFO",  # 這項通常做資訊揭露盤點，對外報告多標 INFO
            "evidence": {
                "DeviceName": device_info.get("DeviceName"),
                "ProductType": device_info.get("ProductType"),
                "ProductVersion": device_info.get("ProductVersion"),
                "BuildVersion": device_info.get("BuildVersion"),
                "UniqueDeviceID": device_info.get("UniqueDeviceID"),
                "SerialNumber": device_info.get("SerialNumber"),
            },
        },
        {
            "id": "V-02",
            "title": "存在描述檔（Configuration Profile）",
            "risk": "Medium",
            "status": "INFO" if (not profiles_checked or cfg_present) else "PASS",
            "evidence": {
                "configuration_profiles_count": cfg_count,
                "has_configuration_profiles": has_cfg,
                "profiles_checked": profiles_checked,
                "profiles_error": profiles_error,
                "configuration_profiles": cfg_profiles,
            },
        },
        {
            "id": "V-03",
            "title": "存在 Provisioning Profile",
            "risk": "Medium",
            "status": "INFO" if (not profiles_checked or prov_present) else "PASS",
            "evidence": {
                "provisioning_profiles_count": prov_count,
                "has_provisioning_profiles": has_prov,
                "profiles_checked": profiles_checked,
                "profiles_error": profiles_error,
            },
        },
        {
            "id": "V-04",
            "title": "安裝 VPN（App 型）",
            "risk": "Medium",
            "status": (
                "INFO"
                if vpn_present or app_list_complete is not True or not profiles_checked
                else "PASS"
            ),
            "evidence": {
                "vpn_present": vpn_present,
                "vpn_apps": vpn_apps,
                "vpn_profile_payloads": vpn_profile_payloads,
                "app_list_complete": app_list_complete,
                "profiles_checked": profiles_checked,
            },
        },
        {
            "id": "V-08",
            "title": "裝置受 MDM 管理（存取受限）",
            "risk": "Low",
            "status": "INFO" if mdm_present else "PASS",
            "evidence": {
                "mdm_payloads_count": len(mdm_payloads),
                "mdm_payloads": mdm_payloads,
                "app_list_complete": app_list_complete,
                "app_list_error": app_list_error,
                "app_list_error_code": app_list_error_code,
                "app_list_error_reason": app_list_error_reason,
                "app_list_error_detail": app_list_error_detail,
            },
        },
        {
            "id": "V-05",
            "title": "具定位能力之 App（能力推定）",
            "risk": "Medium",
            "status": (
                "INFO" if location_apps else ("PASS" if app_list_complete else "INFO")
            ),
            "evidence": {
                "apps": location_apps,
                "count": len(location_apps),
                "location_summary": location_summary,
                "location_features": location_features,
                "location_evidence": location_evidence,
                "app_list_complete": app_list_complete,
            },
        },
        {
            "id": "V-06",
            "title": "同帳號可多裝置登入 App（能力推定）",
            "risk": "Medium",
            "status": (
                "INFO" if multi_device_apps else ("PASS" if app_list_complete else "INFO")
            ),
            "evidence": {
                "apps": multi_device_apps,
                "count": len(multi_device_apps),
                "app_list_complete": app_list_complete,
            },
        },
        {
            "id": "V-07",
            "title": "疑似非 App Store 來源 App",
            "risk": "High",
            # 你要求對外交付：此項若命中通常視為高風險（FAIL）
            "status": (
                "FAIL"
                if non_appstore_apps
                else ("PASS" if app_list_complete else "INFO")
            ),
            "evidence": {
                "apps": non_appstore_apps,
                "count": len(non_appstore_apps),
                "app_list_complete": app_list_complete,
            },
        },
        {
            "id": "V-09",
            "title": "第三方支付工具（可能推定消費地點）",
            "risk": "Medium",
            "status": (
                "INFO"
                if payment_apps
                else ("PASS" if app_list_complete else "INFO")
            ),
            "evidence": {
                "apps": payment_apps,
                "count": len(payment_apps),
                "app_list_complete": app_list_complete,
                "payment_evidence": payment_evidence,
            },
        },
    ]

    # 統計
    stat = {"PASS": 0, "INFO": 0, "FAIL": 0}
    for f in findings:
        stat[f["status"]] = stat.get(f["status"], 0) + 1

    scan_overview_raw = [
        {"category": "描述檔", "source": "Configuration Profiles", "detail": cfg_detail},
        {"category": "描述檔", "source": "Provisioning Profiles", "detail": prov_detail},
        {"category": "描述檔", "source": "MDM Payloads", "detail": mdm_detail},
        {"category": "描述檔", "source": "VPN Payloads", "detail": vpn_payload_detail},
        {"category": "App", "source": "使用者安裝 App", "detail": app_list_detail},
    ]
    if store_found or store_not_found or store_errors:
        scan_overview_raw.append(
            {
                "category": "App Store",
                "source": "查詢結果",
                "detail": (
                    f"found={len(store_found)}, "
                    f"not_found={len(store_not_found)}, "
                    f"errors={len(store_errors)}"
                ),
            }
        )
    inference_overview = [
        {"category": "推定分類", "source": "具定位能力 App", "detail": f"count={len(location_apps)}"},
        {"category": "推定分類", "source": "同帳號可多裝置登入 App", "detail": f"count={len(multi_device_apps)}"},
        {"category": "推定分類", "source": "VPN App", "detail": f"count={len(vpn_apps)}"},
        {"category": "推定分類", "source": "疑似非 App Store", "detail": f"count={len(non_appstore_apps)}"},
        {"category": "推定分類", "source": "第三方支付工具", "detail": f"count={len(payment_apps)}"},
    ]

    return {
        "device_info": device_info,
        "findings": findings,
        "summary_counts": stat,
        "app_store_lookup_summary": app_store_summary,
        "scan_overview_raw": scan_overview_raw,
        "inference_overview": inference_overview,
        "apps_list": apps_list,
    }


def md_escape(s):
    if s is None:
        return ""
    return str(s).replace("|", "\\|")


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


def dedupe_keep_order(values):
    seen = set()
    out = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def summarize_values(values, limit=5):
    values = [v for v in values if v]
    values = dedupe_keep_order(values)
    if not values:
        return ""
    if len(values) > limit:
        return ", ".join(values[:limit]) + f" (+{len(values) - limit} more)"
    return ", ".join(values)


def collect_labels(items, keys):
    labels = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = item.get(key)
            if value:
                labels.append(str(value))
                break
    return labels


def build_app_store_map(app_store_summary: dict) -> dict:
    found = app_store_summary.get("found") or []
    app_store_map = {}
    for item in found:
        if not isinstance(item, dict):
            continue
        bundle_id = item.get("bundle_id")
        if not bundle_id:
            continue
        app_store_map[bundle_id.strip().lower()] = {
            "country": item.get("country"),
            "primary_genre": item.get("primary_genre"),
        }
    return app_store_map


def extract_classification_sets(findings: list[dict]) -> dict:
    def to_set(items):
        out = set()
        for item in items:
            if isinstance(item, str) and item:
                out.add(item.strip().lower())
        return out

    location_apps = []
    multi_device_apps = []
    vpn_apps = []
    non_store_apps = []
    payment_apps = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        ev = finding.get("evidence") or {}
        fid = finding.get("id")
        if fid == "V-05":
            location_apps = ev.get("apps") or []
        elif fid == "V-06":
            multi_device_apps = ev.get("apps") or []
        elif fid == "V-04":
            vpn_apps = ev.get("vpn_apps") or []
        elif fid == "V-07":
            non_store_apps = ev.get("apps") or []
        elif fid == "V-09":
            payment_apps = ev.get("apps") or []

    return {
        "location": to_set(location_apps),
        "multi_device": to_set(multi_device_apps),
        "vpn": to_set(vpn_apps),
        "non_store": to_set(non_store_apps),
        "payment": to_set(payment_apps),
    }


def enrich_apps_list(apps_list: list[dict], app_store_summary: dict, findings: list[dict]) -> list[dict]:
    app_store_map = build_app_store_map(app_store_summary)
    sets = extract_classification_sets(findings)
    enriched = []

    for app in apps_list:
        if not isinstance(app, dict):
            continue
        bundle_id = app.get("bundle_id")
        if not bundle_id:
            continue
        key = bundle_id.strip().lower()
        tags = []
        if key in sets["location"]:
            tags.append("定位能力")
        if key in sets["multi_device"]:
            tags.append("多裝置登入")
        if key in sets["vpn"]:
            tags.append("VPN")
        if key in sets["non_store"]:
            tags.append("疑似非 App Store")
        if key in sets["payment"]:
            tags.append("第三方支付工具")
        classification = "暫無疑慮" if not tags else "、".join(tags)
        store = app_store_map.get(key, {})
        enriched.append(
            {
                "bundle_id": bundle_id,
                "display_name": strip_bidi_controls(app.get("display_name")),
                "version": app.get("version"),
                "classification": classification,
                "has_flags": bool(tags),
                "app_store_country": store.get("country"),
                "app_store_primary_genre": store.get("primary_genre"),
            }
        )

    return enriched


def render_markdown(device_block: dict, report_meta: dict) -> str:
    di = device_block["device_info"]
    findings = device_block["findings"]
    scan_overview_raw = device_block.get("scan_overview_raw") or []
    inference_overview = device_block.get("inference_overview") or []
    apps_list = device_block.get("apps_list") or []

    lines = []
    lines.append("# 行動裝置弱點掃描評估報告（自動彙總）")
    lines.append("")
    lines.append("## 文件資訊")
    lines.append("")
    lines.append("| 項目 | 內容 |")
    lines.append("|---|---|")
    lines.append(f"| 報告產出時間 | {md_escape(report_meta.get('generated_at'))} |")
    lines.append(f"| 來源檔案 | {md_escape(report_meta.get('source_file'))} |")
    lines.append(f"| 掃描方式 | USB 連線（非侵入式） |")
    lines.append("")
    lines.append("## 裝置資訊")
    lines.append("")
    lines.append("| 欄位 | 值 |")
    lines.append("|---|---|")
    lines.append(f"| 裝置名稱 | {md_escape(di.get('DeviceName'))} |")
    lines.append(f"| 裝置型號 | {md_escape(di.get('ProductType'))} |")
    lines.append(f"| iOS 版本 | {md_escape(di.get('ProductVersion'))} |")
    lines.append(f"| Build | {md_escape(di.get('BuildVersion'))} |")
    lines.append(f"| UDID | {md_escape(di.get('UniqueDeviceID'))} |")
    lines.append(f"| Serial | {md_escape(di.get('SerialNumber'))} |")
    lines.append("")
    if scan_overview_raw:
        lines.append("## 掃描到的資料")
        lines.append("")
        lines.append("| 類別 | 來源 | 內容 |")
        lines.append("|---|---|---|")
        for row in scan_overview_raw:
            lines.append(
                f"| {md_escape(row.get('category'))} | "
                f"{md_escape(row.get('source'))} | "
                f"{md_escape(row.get('detail'))} |"
            )
        lines.append("")
    if inference_overview:
        lines.append("## 推定分類摘要")
        lines.append("")
        lines.append("| 項目 | 內容 |")
        lines.append("|---|---|")
        for row in inference_overview:
            lines.append(
                f"| {md_escape(row.get('source'))} | "
                f"{md_escape(row.get('detail'))} |"
            )
        lines.append("")

    lines.append("## 詳細清單")
    lines.append("")

    finding_map = {f.get("id"): f for f in findings if isinstance(f, dict)}

    # 描述檔與設定
    lines.append("### 描述檔與設定")
    lines.append("")

    cfg = finding_map.get("V-02") or {}
    cfg_profiles = (cfg.get("evidence") or {}).get("configuration_profiles") or []
    lines.append("#### Configuration Profiles")
    if not cfg_profiles:
        lines.append("- （無）")
    else:
        for profile in cfg_profiles:
            if not isinstance(profile, dict):
                lines.append(f"- {md_escape(str(profile))}")
                continue
            parts = []
            display_name = profile.get("display_name")
            identifier = profile.get("identifier")
            uuid = profile.get("uuid")
            organization = profile.get("organization")
            removal_disallowed = profile.get("removal_disallowed")
            version = profile.get("version")
            if display_name:
                parts.append(f"name={display_name}")
            if identifier:
                parts.append(f"id={identifier}")
            if uuid:
                parts.append(f"uuid={uuid}")
            if organization:
                parts.append(f"org={organization}")
            if version is not None:
                parts.append(f"version={version}")
            if removal_disallowed is not None:
                parts.append(f"removal_disallowed={removal_disallowed}")
            lines.append(f"- {md_escape(' | '.join(parts))}" if parts else "- (profile)")
    lines.append("")

    prov = finding_map.get("V-03") or {}
    prov_count = (prov.get("evidence") or {}).get("provisioning_profiles_count")
    lines.append("#### Provisioning Profiles")
    if prov_count:
        lines.append(f"- count={md_escape(prov_count)}")
    else:
        lines.append("- （無）")
    lines.append("")

    mdm = finding_map.get("V-08") or {}
    mdm_payloads = (mdm.get("evidence") or {}).get("mdm_payloads") or []
    lines.append("#### MDM Payloads")
    if mdm_payloads:
        for payload in mdm_payloads:
            if not isinstance(payload, dict):
                lines.append(f"- {md_escape(str(payload))}")
                continue
            parts = []
            payload_type = payload.get("payload_type")
            payload_id = payload.get("payload_identifier")
            display_name = payload.get("payload_display_name")
            confidence = payload.get("confidence")
            if payload_type:
                parts.append(f"type={payload_type}")
            if payload_id:
                parts.append(f"id={payload_id}")
            if display_name:
                parts.append(f"name={display_name}")
            if confidence:
                parts.append(f"confidence={confidence}")
            lines.append(f"- {md_escape(' | '.join(parts))}" if parts else "- (unknown payload)")
    else:
        lines.append("- （無）")
    lines.append("")

    vpn = finding_map.get("V-04") or {}
    vpn_payloads = (vpn.get("evidence") or {}).get("vpn_profile_payloads") or []
    lines.append("#### VPN Payloads")
    if vpn_payloads:
        for payload in vpn_payloads:
            if not isinstance(payload, dict):
                lines.append(f"- {md_escape(str(payload))}")
                continue
            parts = []
            payload_type = payload.get("payload_type")
            payload_id = payload.get("payload_identifier")
            display_name = payload.get("payload_display_name")
            confidence = payload.get("confidence")
            if payload_type:
                parts.append(f"type={payload_type}")
            if payload_id:
                parts.append(f"id={payload_id}")
            if display_name:
                parts.append(f"name={display_name}")
            if confidence:
                parts.append(f"confidence={confidence}")
            lines.append(f"- {md_escape(' | '.join(parts))}" if parts else "- (unknown payload)")
    else:
        lines.append("- （無）")
    lines.append("")

    # 推定分類清單
    lines.append("### 推定分類清單")
    lines.append("")

    loc = finding_map.get("V-05") or {}
    loc_ev = loc.get("evidence") or {}
    apps = loc_ev.get("apps") or []
    summary = loc_ev.get("location_summary") or {}
    features = loc_ev.get("location_features") or {}
    evidence = loc_ev.get("location_evidence") or {}
    lines.append("#### 具定位能力 App")
    if not apps:
        lines.append("- （無）")
        lines.append("")
    else:
        if isinstance(summary, dict) and summary:
            lines.append(
                "- Summary: "
                f"high={summary.get('high',0)}, "
                f"medium={summary.get('medium',0)}, "
                f"low={summary.get('low',0)}"
            )
        if isinstance(features, dict) and features:
            for feature_id in sorted(features.keys()):
                feature = features.get(feature_id) or {}
                label = feature.get("label") or feature_id
                confidence = feature.get("confidence") or ""
                f_apps = feature.get("apps") or []
                count = len(f_apps)
                apps_txt = ", ".join(sorted(f_apps))
                if apps_txt:
                    lines.append(
                        f"- Feature: {md_escape(label)} "
                        f"({md_escape(confidence)}) "
                        f"count={count} apps={md_escape(apps_txt)}"
                    )
                else:
                    lines.append(
                        f"- Feature: {md_escape(label)} "
                        f"({md_escape(confidence)}) "
                        f"count={count}"
                    )
        if isinstance(evidence, dict) and evidence:
            for bundle_id in sorted(apps):
                app_ev = evidence.get(bundle_id) or {}
                display = app_ev.get("display_name")
                confidence = app_ev.get("confidence")
                matches = app_ev.get("matches") or []
                match_labels = []
                for match in matches:
                    label = match.get("feature_label") or match.get("feature_id") or ""
                    details = []
                    keywords = match.get("keywords") or []
                    if keywords:
                        details.append(f"kw={', '.join(keywords)}")
                    genre = match.get("genre")
                    if genre:
                        details.append(f"genre={genre}")
                    source = match.get("source")
                    if source:
                        details.append(f"source={source}")
                    if details:
                        label = f"{label} ({'; '.join(details)})"
                    if label:
                        match_labels.append(label)
                match_txt = ", ".join(match_labels)
                parts = [f"App: {bundle_id}"]
                if display:
                    parts.append(f"name={display}")
                if confidence:
                    parts.append(f"confidence={confidence}")
                if match_txt:
                    parts.append(f"matches={match_txt}")
                lines.append(f"- {md_escape(' | '.join(parts))}")
        else:
            for a in apps:
                lines.append(f"- {md_escape(a)}")
        lines.append("")

    multi = finding_map.get("V-06") or {}
    multi_apps = (multi.get("evidence") or {}).get("apps") or []
    lines.append("#### 同帳號可多裝置登入 App")
    if not multi_apps:
        lines.append("- （無）")
    else:
        for a in multi_apps:
            lines.append(f"- {md_escape(a)}")
    lines.append("")

    vpn_apps = (vpn.get("evidence") or {}).get("vpn_apps") or []
    lines.append("#### VPN App")
    if not vpn_apps:
        lines.append("- （無）")
    else:
        for a in vpn_apps:
            lines.append(f"- {md_escape(a)}")
    lines.append("")

    non = finding_map.get("V-07") or {}
    non_apps = (non.get("evidence") or {}).get("apps") or []
    lines.append("#### 疑似非 App Store 來源 App")
    if not non_apps:
        lines.append("- （無）")
    else:
        for a in non_apps:
            lines.append(f"- {md_escape(a)}")
    lines.append("")

    pay = finding_map.get("V-09") or {}
    pay_ev = pay.get("evidence") or {}
    pay_apps = pay_ev.get("apps") or []
    pay_detail = pay_ev.get("payment_evidence") or {}
    lines.append("#### 第三方支付工具（可能推定消費地點）")
    if not pay_apps:
        lines.append("- （無）")
    else:
        for a in pay_apps:
            detail = pay_detail.get(a) or {}
            parts = [f"App: {a}"]
            name = detail.get("display_name")
            if name:
                parts.append(f"name={name}")
            matched = detail.get("matched_keywords") or []
            if matched:
                parts.append(f"kw={', '.join(matched)}")
            lines.append(f"- {md_escape(' | '.join(parts))}")
    lines.append("")

    if apps_list:
        enriched = enrich_apps_list(
            apps_list,
            device_block.get("app_store_lookup_summary") or {},
            findings,
        )
        flagged = [app for app in enriched if app.get("has_flags")]
        clear = [app for app in enriched if not app.get("has_flags")]

        def render_apps_table(title: str, rows: list[dict]):
            lines.append(f"#### {title}")
            if not rows:
                lines.append("- （無）")
                lines.append("")
                return
            lines.append("| Bundle ID | 名稱 | 版本 | 分類 | App Store 國家 | App Store 類別 |")
            lines.append("|---|---|---|---|---|---|")
            for row in rows:
                lines.append(
                    f"| {md_escape(row.get('bundle_id'))} | "
                    f"{md_escape(row.get('display_name'))} | "
                    f"{md_escape(row.get('version'))} | "
                    f"{md_escape(row.get('classification'))} | "
                    f"{md_escape(row.get('app_store_country'))} | "
                    f"{md_escape(row.get('app_store_primary_genre'))} |"
                )
            lines.append("")

        lines.append("### 完整 App 清單（分類）")
        lines.append("")
        render_apps_table("有疑慮", flagged)
        render_apps_table("暫無疑慮", clear)

    app_store_summary = device_block.get("app_store_lookup_summary") or {}
    found = app_store_summary.get("found") or []
    not_found = app_store_summary.get("not_found") or []
    errors = app_store_summary.get("errors") or []
    if found or not_found or errors:
        def format_app_store_entry(item: dict) -> str:
            parts = []
            bundle_id = item.get("bundle_id")
            if bundle_id:
                parts.append(bundle_id)
            name = item.get("track_name") or item.get("display_name")
            if name:
                parts.append(f"name={name}")
            country = item.get("country")
            if country:
                parts.append(f"country={country}")
            countries = item.get("countries_tried") or []
            if countries:
                parts.append(f"countries={','.join(countries)}")
            errors_list = item.get("errors") or []
            if errors_list:
                parts.append(f"errors={'; '.join(errors_list)}")
            if item.get("partial"):
                parts.append("partial=True")
            return md_escape(" | ".join(parts)) if parts else "(unknown)"

        lines.append("### App Store 查詢結果")
        if found:
            lines.append("- Found:")
            for item in found:
                lines.append(f"  - {format_app_store_entry(item)}")
        if not_found:
            lines.append("- Not found:")
            for item in not_found:
                lines.append(f"  - {format_app_store_entry(item)}")
        if errors:
            lines.append("- Errors:")
            for item in errors:
                lines.append(f"  - {format_app_store_entry(item)}")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Convert iOS scan JSON to external delivery report fields")
    parser.add_argument("--in", dest="inp", required=True, help="Input JSON: current_state.json or event report JSON")
    parser.add_argument("--outdir", default="./out_report", help="Output directory")
    args = parser.parse_args()

    data = load_json(args.inp)
    os.makedirs(args.outdir, exist_ok=True)

    # 兼容兩種輸入：
    # 1) current_state.json：含 devices
    # 2) 單一事件 JSON：含 device_info/profiles/apps/vpn
    if "devices" in data and isinstance(data["devices"], dict) and data["devices"]:
        # 取第一台裝置（對外交付通常一台一份；若多台可自行迴圈）
        udid = next(iter(data["devices"].keys()))
        device = data["devices"][udid]
        device_block = build_findings_for_device(device)
    else:
        # 將 event JSON 包成同結構
        device = {
            "device_info": data.get("device_info") or {},
            "profiles": data.get("profiles") or {},
            "apps": data.get("apps") or {},
            "vpn": data.get("vpn") or {},
        }
        device_block = build_findings_for_device(device)

    report_meta = {
        "generated_at": iso_now_local(),
        "source_file": os.path.abspath(args.inp),
    }

    apps_list = device_block.get("apps_list", []) if isinstance(device_block, dict) else []
    enriched_apps = []
    if apps_list and isinstance(device_block, dict):
        enriched_apps = enrich_apps_list(
            apps_list,
            device_block.get("app_store_lookup_summary") or {},
            device_block.get("findings") or [],
        )
    # 輸出 JSON（標準化結構）
    summary_path = os.path.join(args.outdir, "report_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(
            {"meta": report_meta, **device_block},
            f,
            ensure_ascii=False,
            indent=2
        )

    # 輸出 Markdown（可直接貼進 Word / Google Doc）
    md = render_markdown(device_block, report_meta)
    md_path = os.path.join(args.outdir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    if enriched_apps:
        enriched_apps = sorted(
            [a for a in enriched_apps if isinstance(a, dict) and a.get("bundle_id")],
            key=lambda item: item.get("bundle_id") or "",
        )
        apps_json_path = os.path.join(args.outdir, "apps_list.json")
        with open(apps_json_path, "w", encoding="utf-8") as f:
            json.dump(
                {"meta": report_meta, "apps": enriched_apps},
                f,
                ensure_ascii=False,
                indent=2,
            )
        apps_csv_path = os.path.join(args.outdir, "apps_list.csv")
        with open(apps_csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "bundle_id",
                    "display_name",
                    "version",
                    "classification",
                    "app_store_country",
                    "app_store_primary_genre",
                ]
            )
            for app in enriched_apps:
                writer.writerow(
                    [
                        app.get("bundle_id") or "",
                        app.get("display_name") or "",
                        app.get("version") or "",
                        app.get("classification") or "",
                        app.get("app_store_country") or "",
                        app.get("app_store_primary_genre") or "",
                    ]
                )

    print(f"[OK] Wrote: {summary_path}")
    print(f"[OK] Wrote: {md_path}")
    if enriched_apps:
        print(f"[OK] Wrote: {apps_json_path}")
        print(f"[OK] Wrote: {apps_csv_path}")


if __name__ == "__main__":
    main()
