# BookIt – Setup Guide

---

## Docker (recommended for production)

The easiest way to run BookIt is with Docker Compose — it starts the app and a MariaDB database together with a single command.

**Prerequisites:** Docker Desktop (or Docker + Docker Compose on Linux)

### 1. Configure secrets

The only values you must set before starting are `JWT_SECRET` and your notification credentials. Pass them as shell environment variables or create a `.env.docker` file:

```bash
# Generate a strong JWT secret
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

```bash
# .env.docker — set these before running docker compose
JWT_SECRET=<paste generated secret here>

# Email notifications (optional — leave blank to disable)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM_EMAIL=you@gmail.com

# SMS notifications via Twilio (optional — leave blank to disable)
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+15551234567
```

> **Note:** Do not set `DB_HOST`, `DB_USER`, or `DB_PASSWORD` in this file — those are managed internally by the compose file.

### 2. Start

```bash
# First run — builds the image and initialises the database
docker compose --env-file .env.docker up -d

# View logs
docker compose logs -f app
```

The schema is imported automatically on first startup. Open **http://localhost:3000** once the app container is healthy.

### 3. Upgrading an existing database

If you're upgrading from a previous version, run the migration files against the running container:

```bash
docker exec -i bookit-db mariadb -u root -prootsecret booking < migrate_v4.sql
docker exec -i bookit-db mariadb -u root -prootsecret booking < migrate_v5.sql
docker exec -i bookit-db mariadb -u root -prootsecret booking < migrate_v6.sql
```

---

## Local development

### Prerequisites
- Node.js 18+
- MariaDB (running locally or on a server)

---

## 1. Database

```bash
# Import the schema (creates the `booking` database and tables)
mariadb -u root -p < schema.sql
```

---

## 2. Environment

```bash
cp .env.example .env
```

Edit `.env` and fill in your MariaDB credentials and a strong `JWT_SECRET`:

```
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=booking
JWT_SECRET=some_random_64_char_string
JWT_EXPIRES_IN=8h
PORT=3000
```

---

## 3. Install dependencies

```bash
npm install
```

---

## 4. Start the server

```bash
# Production
npm start

# Development (auto-reload)
npm run dev
```

Open **http://localhost:3000** for the public calendar.  
Open **http://localhost:3000/admin.html** for the admin panel.

---

## Default admin credentials

| Username | Password   |
|----------|------------|
| admin    | Admin1234! |

**Change the password immediately** after first login via Admin → Settings → Change Password.

---

## Features

### Public calendar
- Month / Week / Day / List views
- Click any date to open a booking form
- Click any event to see details + download `.ics`
- Filter by resource using the sidebar
- Timezone selector — all times displayed in your chosen zone
- Light / dark theme toggle

### Admin panel
- Dashboard with live stats
- Full appointment table with search + filter
- Edit appointment title, times, status, and contact info
- Download `.ics` for any appointment
- Add / edit / delete resources with color picker
- Change admin password

---

## API reference (brief)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/resources` | — | List resources |
| POST | `/api/resources` | Admin | Add resource |
| PUT | `/api/resources/:id` | Admin | Update resource |
| DELETE | `/api/resources/:id` | Admin | Delete resource |
| GET | `/api/appointments` | — | List appointments (`?resource_id=&start=&end=&status=`) |
| POST | `/api/appointments` | — | Create appointment |
| PUT | `/api/appointments/:id` | Admin | Update appointment |
| DELETE | `/api/appointments/:id` | Admin | Delete appointment |
| GET | `/api/appointments/:id/ics` | — | Download ICS file |
| POST | `/api/admin/login` | — | Admin login → JWT |
| PUT | `/api/admin/password` | Admin | Change password |
