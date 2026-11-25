# VoltageSec Website

Node.js and Express web interface for the VoltageSec obfuscator. Users sign in with
Discord and run obfuscation from the browser. Obfuscation is executed by the
Python compiler through `website/obfuscate.py`.

## Local run

```bash
cd website
npm install
cp .env.example .env
# edit .env
npm start
```

Open http://127.0.0.1:3000.

## Required environment

- `SESSION_SECRET`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`
- `SITE_URL`
- `MAX_SOURCE_BYTES` (optional, default 200000)
- `PYTHON_BIN` (optional, default `python3`)

Discord OAuth redirect URI must exactly match the value configured in the Discord
developer portal, for example:

```text
https://your-service.onrender.com/auth/discord/callback
```

## Render

- Runtime: Node
- Root directory: `website`
- Build command: `npm install`
- Start command: `node server.js`
- Health check path: `/health`

The included root `render.yaml` defines this service.

## GitHub upload

From the repository root:

```bash
git init
git add .
git commit -m "Add VoltageSec Node website"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

Then create the Render service from that GitHub repository.
EOF