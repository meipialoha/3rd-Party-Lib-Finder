# 3rd-Party-Lib-Finder

一支使用 NVD CVE API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) 檢查第三方套件版本是否存在高風險漏洞（CVSS >= 7.0）的簡易 CLI。以套件名稱＋版本做 keyword search 並列出符合門檻的 CVE。執行檔：`LIB_SEARCH.py`。執行時會顯示 API 名稱、端點、掃描開始/結束時間與耗時，方便截圖佐證。

## 功能
- 讀取貼上輸入或專案根目錄的 `libs.txt`（選項 2 固定使用此檔，無需再提供自訂 TXT 路徑）
- 自動解析 `名稱-版本` 或 `名稱_版本`（接受 `v` 前綴）並去重複
- 若缺少 `libs.txt` 會自動建立模板；掃描後可選擇將去重、正規化後的清單覆寫回檔案
- 呼叫 NVD CVE API 以名稱＋版本關鍵字查詢，僅輸出高風險項目
- 以 CVSS 分數排序並列出對應 NVD 詳細頁，逐一呈現每個輸入項；若查無結果會標示 `NO RESULT`

## 環境需求
- Python 3.9+（建議使用虛擬環境）
- 需要可存取 `https://services.nvd.nist.gov/rest/json/cves/2.0` 的網路環境；未設 API Key 時請留意 NVD 的速率限制。
- 依賴套件：`requests`、`colorama`（執行時會自動安裝 `requests>=2.31.0` / `colorama>=0.4.6`，也可手動用 `pip install -r requirement.txt`）
- 可選：設定環境變數 `NVD_API_KEY` 以提升 NVD API 配額。

## 安裝
自動安裝：直接執行腳本，若缺少 `requests` 會透過 pip 安裝（需網路與 pip 權限）。

手動安裝（可選）：
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirement.txt
```

## 使用方式
```bash
python LIB_SEARCH.py
```
- 選項 1：直接貼上多行輸入，空白行結束。
- 選項 2：使用與 `LIB_SEARCH.py` 同目錄的 `libs.txt`。若檔案不存在會建立帶註解的模板並暫停，編輯後按 Enter 繼續；掃描後會詢問是否用去重後的清單覆蓋 `libs.txt`。

### 輸入格式範例
`libs.txt` 或貼上內容皆為每行一筆：
```
Firebase-10.24.0
AFNetworking-4.0.1
DPHSDK-v3.4.3
```
- 若無法解析版本會改以名稱查詢；版本前的 `v` 會自動移除。

### 輸出範例
```
=== CYBER VULN SCAN ===
 API      : NIST NVD CVE API (2.0)
 Endpoint : https://services.nvd.nist.gov/rest/json/cves/2.0
 Started  : 2025-01-15T12:34:56.789Z

>>>[ Firebase-10.24.0 ]<<<
 :: CVE CVE-2023-XXXX | CVSS 9.8
    簡述內容
    https://nvd.nist.gov/vuln/detail/CVE-2023-XXXX

>>>[ UnknownLib-1.0.0 ]<<<
 :: NO RESULT

=== SCAN COMPLETE ===
 Finished : 2025-01-15T12:35:01.123Z
 Duration : 4.33 seconds
 Source   : Results based on NIST NVD CVE API
```

## 設定
- 風險門檻：`HIGH_RISK_CVSS_THRESHOLD`（預設 7.0）。
- NVD API Key：設 `NVD_API_KEY` 可提升配額並降低 429 的機率。

## 注意事項
- 選項 2 固定讀取 `libs.txt`，不需輸入檔案路徑；若檔案為只讀，覆寫步驟會失敗。
- 若環境無法自動安裝套件，請改用手動安裝流程。
- 只會列出能取得 CVSS 分數且達到門檻的漏洞；若無 CVSS 分數則不列出。
- NVD 未必能以 keyword search 精準匹配所有套件/版本，若查詢結果為 0，可嘗試調整名稱或版本格式。
- 每個輸入都會輸出一個區塊，若未命中則顯示 `NO RESULT`。
- 終端輸出採用色彩標示（使用 `colorama`，跨 Windows/macOS/Linux）；若色彩庫安裝失敗仍可顯示文字結果。
- 若缺少版本資訊，會直接以套件名稱查詢（結果可能較寬），模式 1 / 模式 2 輸出一致。
