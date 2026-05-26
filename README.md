# Thiranex Secure Login App

A simple secure authentication demo built with Node.js, Express, and SQLite.

## Features

- User registration with bcrypt password hashing
- Login with session management
- Logout
- Input validation and protection against SQL injection using prepared statements
- Optional 2FA via TOTP and QR code

## Install

1. Open PowerShell in `d:\thiranex-4`
2. Run:
   ```powershell
   npm install
   npm start
   ```

## Run

Open `http://localhost:3000` in your browser.

If you want to share the app on a local network, use `http://<your-machine-ip>:3000` after starting the server.

## Notes

- The app stores users in `auth.db` using SQLite.
- Passwords are hashed with bcrypt.
- Session cookies are configured securely for development.
