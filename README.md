# iOS USB Security Assessment Toolset

Non-invasive iOS device security assessment over USB on macOS.  
This toolset inventories device metadata, summarizes profile signals, enumerates user-installed apps, and produces an external-delivery friendly report summary.

## Scope
- Device metadata inventory (udid, model, iOS version, build, etc.)
- Configuration profile / provisioning profile presence summary (device-level)
- User-installed app inventory (bundle identifiers)
- App capability classification (capability-based / heuristic):
  - Location-capable apps
  - Multi-device login capable apps (service capability, not real-time state)
  - Suspected non–App Store apps (requires explicit tagging or MDM for verification)
- VPN presence (practical signal based on VPN app installation)

## Important Notes
- This tool does NOT jailbreak, bypass iOS security controls, or access app/user content.
- App classifications are capability-based heuristics, not proof of current permissions, login status, or active usage.
- Do NOT commit customer scan outputs (reports) into the repository.

## Optional Accuracy Signals
- Bundle ID overrides: `rules/app_bundle_overrides.json`
- App Store metadata lookup (sends bundle IDs to Apple): `python3 tools/ios_usb_audit.py --app-store`
  - Cache: `./cache/app_store_cache.json`
- VPN profile payload detection (via `cfgutil` JSON payloads)

## Requirements (macOS)
Install dependencies:
