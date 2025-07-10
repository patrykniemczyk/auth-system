# auth-system

A Node.js/Express.js authentication module using username-based login, JWTs with refresh tokens, role‑based access control, and token revocation backed by PostgreSQL.

## Features

- Username-based registration and login
- JWT access tokens with revocation (jti)
- Refresh tokens stored in DB
- Role-based access control
- Token revocation list

## Setup

1. **Clone or copy the module files**
2. **Install dependencies:**

   ```sh
   npm install
   ```

3. **Configure environment variables:**
   Edit `.env`:

   ```env
   DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/DATABASE
   JWT_ACCESS_SECRET=your_access_secret
   JWT_REFRESH_SECRET=your_refresh_secret
   ACCESS_TOKEN_TTL=15m
   REFRESH_TOKEN_TTL=7d
   ```

4. **Run database migrations:**

   ```sh
   npx prisma migrate dev --name init
   ```

5. **Start the server:**

   ```sh
   npm start
   ```

## API Endpoints

### POST `/auth/register`

- Body: `{ "username": "string", "password": "string" }`
- Registers a new user.

### POST `/auth/login`

- Body: `{ "username": "string", "password": "string" }`
- Returns: `{ accessToken, refreshToken }`

### POST `/auth/refresh`

- Body: `{ "refreshToken": "string" }`
- Returns: `{ accessToken }`

### POST `/auth/logout`

- Body: `{ "refreshToken": "string" }`
- Logs out the user (removes refresh token).

## Middleware Usage

Import and use in your routes:

```js
import { authenticateToken, authorizeRoles } from './src/middlewares/auth.js';

app.get('/protected', authenticateToken, (req, res) => {
  res.send('Protected!');
});

app.get('/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.send('Admin only!');
});
```

## Customization

- Adjust roles, token TTLs, or add new endpoints as needed.
- See `/src/controllers/authController.js` for core logic.
