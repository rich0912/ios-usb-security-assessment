import importlib.util
import os
import unittest


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IOS_AUDIT = load_module(os.path.join(ROOT, "tools", "ios_usb_audit.py"), "ios_usb_audit")


class TestAppRules(unittest.TestCase):
    def test_load_app_rules(self):
        rules = IOS_AUDIT.load_app_rules(os.path.join(ROOT, "rules", "app_rules.json"))
        location_ids = {rule["id"] for rule in rules["location_features"]}
        self.assertIn("navigation_maps", location_ids)
        self.assertIn("telegram", rules["multi_device_login_keywords"])
        self.assertIn("openvpn", rules["vpn_keywords"])
        self.assertIn("alipay", rules["payment_keywords"])
        self.assertIn("tw", rules["app_store_countries"])
        travel = next(
            rule for rule in rules["app_store_category_rules"] if rule["genre"] == "Travel"
        )
        self.assertTrue(travel["requires_signal"])

    def test_classify_apps_uses_rules(self):
        rules = IOS_AUDIT.load_app_rules(os.path.join(ROOT, "rules", "app_rules.json"))
        apps = [
            {"bundle_id": "com.example.maps", "display_name": "Maps", "version": "1.0"},
            {"bundle_id": "com.example.telegram", "display_name": "Telegram", "version": "1.0"},
            {"bundle_id": "com.example.openvpn", "display_name": "OpenVPN", "version": "1.0"},
            {"bundle_id": "com.example.travel", "display_name": "TravelApp", "version": "1.0"},
            {"bundle_id": "com.example.internal", "display_name": "InternalApp", "version": "1.0"},
            {"bundle_id": "com.example.alipay", "display_name": "Alipay", "version": "1.0"},
        ]
        app_store_data = {
            "com.example.travel": {
                "found": True,
                "primary_genre": "Travel",
                "genres": ["Travel"],
            },
            "com.example.internal": {
                "found": False,
                "checked_at": "2025-01-01T00:00:00Z",
                "not_found": True,
                "countries_tried": ["us"],
            },
        }
        bundle_overrides = {"location": {}, "location_exclude": set(), "vpn": set()}
        classification = IOS_AUDIT.classify_apps(
            apps,
            profiles=None,
            apps_error=None,
            bundle_overrides=bundle_overrides,
            app_store_data=app_store_data,
            app_rules=rules,
        )
        location_items = classification["location_capable_apps"]["items"]
        self.assertIn("com.example.maps", location_items)
        self.assertNotIn("com.example.travel", location_items)
        self.assertIn(
            "com.example.telegram",
            classification["multi_device_login_capable_apps"]["items"],
        )
        self.assertIn(
            "com.example.openvpn",
            classification["vpn_apps_detected"]["items"],
        )
        self.assertIn(
            "com.example.internal",
            classification["non_app_store_suspected_apps"]["items"],
        )
        self.assertIn(
            "com.example.alipay",
            classification["payment_apps"]["items"],
        )


if __name__ == "__main__":
    unittest.main()
