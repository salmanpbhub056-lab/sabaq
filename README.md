# Sabaq – Tutor & Academy Finder for Karachi

Static front end (`index.html`) plus one serverless function (`api/admin.js`) for the admin login.

## Features
- **Students/parents:** search & filters (Urdu/Roman Urdu), compare, save, demo requests (validated, rate-limited), verified-only reviews (one per listing, moderated), reports, smart match, fees, exam countdown, mock tests, resources, study groups, notifications, EN/اردو.
- **Tutors/academies:** sign-up, profile photo, private document upload (degree, ID, certificate), listing review workflow, verification status, request inbox (accept/decline), public replies to reviews, profile-view stats, edit and delete.
- **Admin (`/admin`, not linked anywhere):** separate email + password login (no sign-up), review queue with document viewer and verification checklist, approve / approve & verify / reject / suspend with reasons, feature listings, user suspend/delete, review and report moderation, activity log, announcement banner, CSV export.

## Deploy on Vercel
1. Import the repo (framework preset: **Other**, no build command).
2. Add environment variables from `.env.example`: `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_SECRET`.
3. Redeploy, then open `/admin`.

If the API is not deployed (e.g. opening the file locally), `/admin` runs in **demo mode** with `admin@sabaq.demo` / `Admin@123`. Demo mode is not secure.

## Important limitation
Accounts, listings, uploads and reviews are stored in each visitor's browser (localStorage). They are **not shared between users or devices**, so a tutor's upload will not appear in another person's admin panel. Passwords are hashed client-side for demonstration only. For production, add a database and storage (e.g. Supabase: Auth, Postgres, Storage with private buckets and row-level security) and move all checks server-side.
