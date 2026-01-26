import importlib.util
import os
import unittest


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
JSON_REPORT = load_module(os.path.join(ROOT, "tools", "json_to_report.py"), "json_to_report")


class TestReportSnapshot(unittest.TestCase):
    def test_markdown_snapshot(self):
        device = {
            "device_info": {
                "DeviceName": "Test iPhone",
                "ProductType": "iPhone15,2",
                "ProductVersion": "17.2",
                "BuildVersion": "21C62",
                "UniqueDeviceID": "00000000-TEST-UDID",
                "SerialNumber": "TESTSERIAL",
            },
            "profiles": {
                "configuration_profiles_count": 1,
                "has_configuration_profiles": True,
                "configuration_profiles": [
                    {
                        "display_name": "Example Profile",
                        "identifier": "profile.example",
                        "uuid": "profile-uuid",
                        "organization": "Example Org",
                        "removal_disallowed": True,
                    }
                ],
                "provisioning_profiles_count": 0,
                "has_provisioning_profiles": False,
                "vpn_payloads_count": 1,
                "has_vpn_payloads": True,
                "vpn_payloads": [
                    {
                        "payload_type": "com.apple.vpn.managed",
                        "payload_identifier": "vpn.example",
                        "payload_display_name": "Example VPN",
                        "payload_uuid": "vpn-uuid",
                        "confidence": "high",
                    }
                ],
                "mdm_payloads_count": 1,
                "has_mdm_payloads": True,
                "mdm_payloads": [
                    {
                        "payload_type": "com.apple.mdm",
                        "payload_identifier": "mdm.example",
                        "payload_display_name": "Example MDM",
                        "payload_uuid": "mdm-uuid",
                        "confidence": "high",
                    }
                ],
            },
            "apps": {
                "app_list_complete": True,
                "app_list_error": None,
                "apps_list": [
                    {"bundle_id": "com.example.maps", "display_name": "Maps", "version": "1.0"},
                    {"bundle_id": "com.example.chat", "display_name": "Chat", "version": "2.1"},
                ],
                "location_capable_apps": {
                    "items": ["com.example.maps"],
                    "summary": {"high": 1, "medium": 0, "low": 0},
                    "features": {
                        "navigation_maps": {
                            "label": "導航/地圖",
                            "confidence": "high",
                            "apps": ["com.example.maps"],
                        }
                    },
                    "evidence": {
                        "com.example.maps": {
                            "display_name": "Maps",
                            "version": "1.0",
                            "confidence": "high",
                            "matches": [
                                {
                                    "feature_id": "navigation_maps",
                                    "feature_label": "導航/地圖",
                                    "confidence": "high",
                                    "source": "keyword",
                                    "keywords": ["maps"],
                                }
                            ],
                        }
                    },
                },
                "multi_device_login_capable_apps": {"items": ["com.example.chat"]},
                "non_app_store_suspected_apps": {"items": []},
                "vpn_apps_detected": {"items": ["com.example.vpn"]},
            },
            "vpn": {
                "present": True,
                "apps": ["com.example.vpn"],
                "profile_payloads": [
                    {
                        "payload_type": "com.apple.vpn.managed",
                        "payload_identifier": "vpn.example",
                        "payload_display_name": "Example VPN",
                        "payload_uuid": "vpn-uuid",
                        "confidence": "high",
                    }
                ],
            },
        }
        device_block = JSON_REPORT.build_findings_for_device(device)
        report_meta = {
            "generated_at": "2025-01-01 00:00:00",
            "source_file": "/tmp/sample.json",
        }
        markdown = JSON_REPORT.render_markdown(device_block, report_meta)
        snapshot_path = os.path.join(ROOT, "tests", "fixtures", "report_snapshot.md")
        with open(snapshot_path, "r", encoding="utf-8") as f:
            expected = f.read()
        self.assertEqual(markdown.strip(), expected.strip())


if __name__ == "__main__":
    unittest.main()
