# PKI 2FA Microservice (Partnr GPP)
Quick setup (local)
1. Ensure Node 18+ is installed.
2. In project root:
   npm ci
   npm run keygen
   npm start
Endpoints:
- POST /decrypt-seed { "encrypted": "<base64>" }
- GET /generate-2fa -> { code, valid_for }
- POST /verify-2fa { "code": "123456" }
Docker:
docker build -t gpp-microservice:latest .
docker run -d --name gpp2fa -p 8080:8080 -v "C:\Gpp_task\data:/data" -v "C:\Gpp_task\cron:/cron" -v "C:\Gpp_task\keys:/app/keys" gpp-microservice:latest
Cron:
cron/mycron runs every minute and executes src/scripts/cronTask.js

