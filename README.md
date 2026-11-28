# Sabaq – Tutor & Academy Finder for Karachi

Static front end (`index.html`) + serverless API (`api/`) + Supabase database.

## Files
- `index.html` – the whole website
- `api/app.js` – all site actions and rules (runs on Vercel, checks everything on the server)
- `api/admin.js` – admin email/password login (no sign-up)
- `api/_lib.js` – shared helpers
- `schema.sql` – database setup (run once in Supabase)

## Setup (summary)
1. Supabase: create project, run `schema.sql` in SQL Editor.
2. GitHub: upload these files to the **root** of a repo.
3. Vercel: import repo (preset "Other"), add the 5 environment variables from `.env.example`, deploy.
4. Open `/admin` and log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

## Notes
- Documents are stored privately in the database and are only returned to a logged-in admin.
- Request limit on Vercel is about 4.5 MB, so documents are limited to 800 KB each.
- Passwords are hashed with scrypt on the server. Sessions are signed HttpOnly cookies.
- The service key gives full database access: keep it only in Vercel's environment variables.
