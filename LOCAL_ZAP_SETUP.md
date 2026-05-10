# Local OWASP ZAP Setup

If the app says ZAP cannot connect while ZAP is open, first check the API directly:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/JSON/core/view/version/
```

If that returns `403 Forbidden`, ZAP is running but requires an API key.

## Option 1: Use The ZAP API Key

In ZAP Desktop:

1. Open `Tools > Options > API`.
2. Copy the API key.
3. Create or edit `.env` in the project root.

The `.env` file must contain only `KEY=value` lines:

```env
SECRET_KEY=dev-secret-change-me
ZAP_PROXY_URL=http://127.0.0.1:8080
ZAP_API_KEY=paste-your-zap-api-key-here
OPENAI_API_KEY=paste-your-openai-key-here-if-needed
```

Then restart Flask:

```powershell
.\venv\Scripts\python.exe app.py
```

## Option 2: Disable The ZAP API Key Locally

In ZAP Desktop:

1. Open `Tools > Options > API`.
2. Disable API key enforcement for local testing.
3. Restart ZAP and Flask.

Only do this for local development. Do not expose ZAP port `8080` publicly.

## If ZAP Uses Another Port

Check `Tools > Options > Network > Local Servers/Proxies` in ZAP, then set:

```env
ZAP_PROXY_URL=http://127.0.0.1:8081
```
