#!/usr/bin/env python3
from __future__ import annotations
import argparse
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

    cfg_count = profiles.get("configuration_profiles_count")
    prov_count = profiles.get("provisioning_profiles_count")
    has_cfg = profiles.get("has_configuration_profiles")
    has_prov = profiles.get("has_provisioning_profiles")
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
    ]

    # 統計
    stat = {"PASS": 0, "INFO": 0, "FAIL": 0}
    for f in findings:
        stat[f["status"]] = stat.get(f["status"], 0) + 1

    return {
        "device_info": device_info,
        "findings": findings,
        "summary_counts": stat,
    }


def md_escape(s):
    if s is None:
        return ""
    return str(s).replace("|", "\\|")


def render_markdown(device_block: dict, report_meta: dict) -> str:
    di = device_block["device_info"]
    counts = device_block["summary_counts"]
    findings = device_block["findings"]

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
    lines.append("## 結果摘要")
    lines.append("")
    lines.append("| PASS | INFO | FAIL |")
    lines.append("|---:|---:|---:|")
    lines.append(f"| {counts.get('PASS',0)} | {counts.get('INFO',0)} | {counts.get('FAIL',0)} |")
    lines.append("")
    lines.append("## 弱點檢測明細")
    lines.append("")
    lines.append("| 編號 | 項目 | 風險等級 | 狀態 | 佐證摘要 |")
    lines.append("|---|---|---|---|---|")

    for f in findings:
        ev = f.get("evidence") or {}
        # 選擇性摘要（避免太長）
        if f["id"] == "V-04":
            ev_txt = (
                f"vpn_present={ev.get('vpn_present')}, "
                f"vpn_apps={len(ev.get('vpn_apps') or [])}, "
                f"vpn_profiles={len(ev.get('vpn_profile_payloads') or [])}"
            )
        elif f["id"] == "V-08":
            ev_txt = (
                f"mdm_payloads={ev.get('mdm_payloads_count')}, "
                f"app_list_error={ev.get('app_list_error_code')}"
            )
        elif f["id"] == "V-05":
            summary = ev.get("location_summary") or {}
            if isinstance(summary, dict) and summary:
                ev_txt = (
                    f"count={ev.get('count')} "
                    f"(high={summary.get('high',0)}, "
                    f"medium={summary.get('medium',0)}, "
                    f"low={summary.get('low',0)})"
                )
            else:
                ev_txt = f"count={ev.get('count')}"
        elif f["id"] in ("V-06", "V-07"):
            ev_txt = f"count={ev.get('count')}"
        elif f["id"] in ("V-02", "V-03"):
            ev_txt = f"count={ev.get('configuration_profiles_count') if f['id']=='V-02' else ev.get('provisioning_profiles_count')}"
        else:
            ev_txt = "device fields collected"
        lines.append(f"| {f['id']} | {md_escape(f['title'])} | {f['risk']} | {f['status']} | {md_escape(ev_txt)} |")

    lines.append("")
    lines.append("## 附錄：命中清單")
    lines.append("")
    for f in findings:
        if f["id"] == "V-05":
            ev = f.get("evidence") or {}
            apps = ev.get("apps") or []
            summary = ev.get("location_summary") or {}
            features = ev.get("location_features") or {}
            evidence = ev.get("location_evidence") or {}
            lines.append(f"### {f['id']} {f['title']}（{f['status']}）")
            if not apps:
                lines.append("- （無）")
                lines.append("")
                continue
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
            continue
        if f["id"] in ("V-06", "V-07"):
            apps = (f.get("evidence") or {}).get("apps") or []
            lines.append(f"### {f['id']} {f['title']}（{f['status']}）")
            if not apps:
                lines.append("- （無）")
            else:
                for a in apps:
                    lines.append(f"- {md_escape(a)}")
            lines.append("")
        if f["id"] == "V-04":
            apps = (f.get("evidence") or {}).get("vpn_apps") or []
            payloads = (f.get("evidence") or {}).get("vpn_profile_payloads") or []
            lines.append(f"### {f['id']} {f['title']}（{f['status']}）")
            if not apps:
                lines.append("- （無）")
            else:
                for a in apps:
                    lines.append(f"- {md_escape(a)}")
            if payloads:
                lines.append("- VPN Profile Payloads:")
                for payload in payloads:
                    if not isinstance(payload, dict):
                        lines.append(f"  - {md_escape(str(payload))}")
                        continue
                    payload_type = payload.get("payload_type")
                    payload_id = payload.get("payload_identifier")
                    display_name = payload.get("payload_display_name")
                    confidence = payload.get("confidence")
                    parts = []
                    if payload_type:
                        parts.append(f"type={payload_type}")
                    if payload_id:
                        parts.append(f"id={payload_id}")
                    if display_name:
                        parts.append(f"name={display_name}")
                    if confidence:
                        parts.append(f"confidence={confidence}")
                    if parts:
                        lines.append(f"  - {md_escape(' | '.join(parts))}")
                    else:
                        lines.append("  - (unknown payload)")
            lines.append("")
        if f["id"] == "V-08":
            ev = f.get("evidence") or {}
            payloads = ev.get("mdm_payloads") or []
            lines.append(f"### {f['id']} {f['title']}（{f['status']}）")
            if ev.get("app_list_error"):
                lines.append(f"- App list error: {md_escape(ev.get('app_list_error'))}")
            if ev.get("app_list_error_code") or ev.get("app_list_error_reason"):
                lines.append(
                    f"- App list error code: {md_escape(ev.get('app_list_error_code'))} "
                    f"reason: {md_escape(ev.get('app_list_error_reason'))}"
                )
            if ev.get("app_list_error_detail"):
                lines.append(f"- Reason detail: {md_escape(ev.get('app_list_error_detail'))}")
            if payloads:
                lines.append("- MDM Payloads:")
                for payload in payloads:
                    if not isinstance(payload, dict):
                        lines.append(f"  - {md_escape(str(payload))}")
                        continue
                    payload_type = payload.get("payload_type")
                    payload_id = payload.get("payload_identifier")
                    display_name = payload.get("payload_display_name")
                    confidence = payload.get("confidence")
                    parts = []
                    if payload_type:
                        parts.append(f"type={payload_type}")
                    if payload_id:
                        parts.append(f"id={payload_id}")
                    if display_name:
                        parts.append(f"name={display_name}")
                    if confidence:
                        parts.append(f"confidence={confidence}")
                    if parts:
                        lines.append(f"  - {md_escape(' | '.join(parts))}")
                    else:
                        lines.append("  - (unknown payload)")
            if not payloads and not ev.get("app_list_error"):
                lines.append("- （無）")
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

    print(f"[OK] Wrote: {summary_path}")
    print(f"[OK] Wrote: {md_path}")


if __name__ == "__main__":
    main()
