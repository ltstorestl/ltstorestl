# ltstorestl-login-app

A Node.js Express web application with MongoDB, EJS templating, user authentication, and an admin setup page.

## Features
- Secure login with username and password
- Admin setup page for creating admin accounts
- Passwords hashed with bcrypt
- Sessions stored in MongoDB
- Modern, responsive UI

## Setup
1. Install dependencies:
   ```bash
   npm install
   ```
2. Create a `.env` file (optional) to override defaults:
   ```env
   MONGODB_URI=your_mongodb_uri
   SESSION_SECRET=your_session_secret
   PORT=3000
   ```
3. Start the server:
   ```bash
   npm start
   ```
4. Visit `http://localhost:3000` in your browser.

## Pages
- `/login` — User login
- `/admin-setup` — Admin account setup
- `/dashboard` — User dashboard (after login)

## Security
- Passwords are hashed using bcrypt
- Sessions are stored securely in MongoDB
- Sensitive data can be managed via environment variables

---

Replace the default MongoDB URI and session secret in production.
