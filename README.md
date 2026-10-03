# Ethio Ministry Exam — Server

A small, secure backend for the app: accounts, subscriptions, payment review, exam content, exercise history, an admin web page, and the privacy / delete-account pages Google Play requires.

* **No `npm install` needed.** It uses only what is built into Node.js 22.13+ (SQLite database, scrypt password hashing).
* Tested: `npm test` runs 37 end-to-end checks (login, premium locking, payments, admin rights, rate limits, account deletion).
* Content: `data/content.json` holds all 2,193 questions exported from your app (version 69).

## 1. Try it on your own computer (5 minutes)
1. Install Node.js 22 LTS from nodejs.org.
2. In this folder: copy `.env.example` to `.env` and fill in `JWT_SECRET`, `ADMIN_PASSWORD`, your payment accounts, `CONTACT_EMAIL`.
   Make a secret with: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
3. `npm run import`  (loads the questions) → `npm start` → open http://localhost:3000/admin and log in with ADMIN_PHONE / ADMIN_PASSWORD.
4. `npm test` to confirm everything works on your machine.

## 2. Put it online (Ubuntu VPS, ~US$5/month)
1. Rent a small VPS (Ubuntu 24.04) and point a domain/subdomain (e.g. api.yourdomain.com) at its IP.
2. `sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx` and install Node 22 (nodesource.com).
3. `sudo adduser --system --group ethio` then upload this folder to `/opt/ethio-exam-server` (`scp` or `git`), `sudo chown -R ethio:ethio /opt/ethio-exam-server`.
4. Create `/opt/ethio-exam-server/.env` (set `NODE_ENV=production`, `TRUST_PROXY=1`, `ALLOWED_ORIGINS=https://localhost,capacitor://localhost`).
5. `cd /opt/ethio-exam-server && sudo -u ethio node scripts/import-content.js`
6. Copy `deploy/ethio-exam.service` to `/etc/systemd/system/`, then `sudo systemctl enable --now ethio-exam`.
7. Copy `deploy/nginx.conf` to `/etc/nginx/sites-available/ethio-exam`, edit the domain, link it into `sites-enabled`, `sudo nginx -t && sudo systemctl reload nginx`, then `sudo certbot --nginx -d api.yourdomain.com` for HTTPS.
8. Check `https://api.yourdomain.com/health`, then `/admin`, `/privacy`, `/delete-account`.
9. **Backups (do not skip):** `crontab -e` as user ethio → `0 2 * * * cd /opt/ethio-exam-server && node scripts/backup.js` and copy `backups/` off the server weekly (your phone/Google Drive).
10. Update later: upload new files, `sudo systemctl restart ethio-exam`. Never delete `data/` or `uploads/`.

## 3. Daily admin work
* `/admin` → **Payments**: view the receipt, check it in your CBE/Telebirr app, Approve or Reject. Flags warn about re-used screenshots/references.
* **Answers to verify**: lists the 226 questions with no confirmed answer so a teacher can set them.
* To add new exams: put them in `data/content.json` format and run `npm run import` (existing questions are never overwritten or duplicated).

## 4. Security rules built in
Passwords hashed (scrypt) · prices decided by the server · only the server unlocks premium · nobody can register as admin · login and API rate limits · receipts checked as real images and stored privately · locked questions are never sent to free users.

## 5. API summary (for the app)
`POST /api/auth/register` `POST /api/auth/login` `GET /api/me` `PATCH /api/me` `DELETE /api/me` (header X-Confirm-Password) `GET /api/config` `GET /api/content/manifest` `GET /api/questions?grade=&subject=&year=` `POST /api/payments` `GET /api/payments/mine` `POST /api/history` `GET /api/history` · admin: `/api/admin/*`.

## 6. IMPORTANT — the app is not connected yet
`ethio-ministry-exam.html` still stores users, payments and questions in the phone's own storage. The server is ready, but the app must be changed to call it (login, load questions, send payment, save history). That is the next step; until then, do not publish the app expecting server-side protection.
