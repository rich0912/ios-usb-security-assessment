# 行動裝置弱點掃描評估報告（自動彙總）

## 文件資訊

| 項目 | 內容 |
|---|---|
| 報告產出時間 | 2025-01-01 00:00:00 |
| 來源檔案 | /tmp/sample.json |
| 掃描方式 | USB 連線（非侵入式） |

## 裝置資訊

| 欄位 | 值 |
|---|---|
| 裝置名稱 | Test iPhone |
| 裝置型號 | iPhone15,2 |
| iOS 版本 | 17.2 |
| Build | 21C62 |
| UDID | 00000000-TEST-UDID |
| Serial | TESTSERIAL |

## 掃描到的資料

| 類別 | 來源 | 內容 |
|---|---|---|
| 描述檔 | Configuration Profiles | count=1, names=Example Profile |
| 描述檔 | Provisioning Profiles | count=0 |
| 描述檔 | MDM Payloads | count=1, names=Example MDM |
| 描述檔 | VPN Payloads | count=1, names=Example VPN |
| App | 使用者安裝 App | count=unknown |

## 推定分類摘要

| 項目 | 內容 |
|---|---|
| 具定位能力 App | count=1 |
| 同帳號可多裝置登入 App | count=1 |
| VPN App | count=1 |
| 疑似非 App Store | count=0 |
| 第三方支付工具 | count=0 |

## 詳細清單

### 描述檔與設定

#### Configuration Profiles
- name=Example Profile \| id=profile.example \| uuid=profile-uuid \| org=Example Org \| removal_disallowed=True

#### Provisioning Profiles
- （無）

#### MDM Payloads
- type=com.apple.mdm \| id=mdm.example \| name=Example MDM \| confidence=high

#### VPN Payloads
- type=com.apple.vpn.managed \| id=vpn.example \| name=Example VPN \| confidence=high

### 推定分類清單

#### 具定位能力 App
- Summary: high=1, medium=0, low=0
- Feature: 導航/地圖 (high) count=1 apps=com.example.maps
- App: com.example.maps \| name=Maps \| confidence=high \| matches=導航/地圖 (kw=maps; source=keyword)

#### 同帳號可多裝置登入 App
- com.example.chat

#### VPN App
- com.example.vpn

#### 疑似非 App Store 來源 App
- （無）

#### 第三方支付工具（可能推定消費地點）
- （無）

### 完整 App 清單（分類）

#### 有疑慮
| Bundle ID | 名稱 | 版本 | 分類 | App Store 國家 | App Store 類別 |
|---|---|---|---|---|---|
| com.example.maps | Maps | 1.0 | 定位能力 |  |  |
| com.example.chat | Chat | 2.1 | 多裝置登入 |  |  |

#### 暫無疑慮
- （無）
