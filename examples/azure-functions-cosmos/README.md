# clawauth example — Azure Functions + Cosmos

Paste your Google OAuth Client ID, run two commands, working sign-in.

## Local dev (5 min)

```
npm install
# 1. Get a Google OAuth Client ID at https://console.cloud.google.com/apis/credentials
#    Authorized JS origins: http://localhost:8080
# 2. Edit clawauth.config.json — paste googleClientId
# 3. (optional) Cosmos emulator OR leave COSMOS_CONN unset to use in-memory dev mode
npm run dev
# → open http://localhost:8080
```

## Deploy to Azure (one shot)

```
az login        # only requirement
npm run deploy
# → prints https://func-xxxxxx.azurewebsites.net
```

What `npm run deploy` does:

1. Validates `az login`
2. Reads `clawauth.config.json`
3. `terraform apply` — provisions RG + Cosmos (serverless, free tier) + Linux Function app + storage + App Insights
4. Generates `CLAWAUTH_JWT_SECRET` (96 hex chars) and sets it as a Function app setting (never written to tfstate)
5. Sets `GOOGLE_CLIENT_ID` + `COSMOS_CONN` app settings (Cosmos key fetched via `az`, never logged)
6. Builds + `func azure functionapp publish`
7. Prints the live URL

Re-run is idempotent. Pass `--rotate-secret` to force JWT secret rotation (old tokens immediately invalid).

## Destroy

```
npm run destroy
```
