import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../server.js';
import { v4 as uuidv4 } from 'uuid';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_ACCESS_SECRET;

// Add a protected test route for middleware testing
app.get('/protected', (req, res) => {
  import('../src/middlewares/auth.js').then(({ authenticateToken }) => {
    authenticateToken(req, res, () => {
      res.json({ user: req.user });
    });
  });
});

app.get('/admin', (req, res) => {
  import('../src/middlewares/auth.js').then(({ authenticateToken, authorizeRoles }) => {
    authenticateToken(req, res, () => {
      authorizeRoles('admin')(req, res, () => {
        res.json({ user: req.user });
      });
    });
  });
});

// Tests for auth middleware
describe('Auth Middleware', () => {
  let userToken, adminToken, revokedJti;
  const userPayload = { sub: 'user-id', username: 'user', role: 'user', jti: uuidv4() };
  const adminPayload = { sub: 'admin-id', username: 'admin', role: 'admin', jti: uuidv4() };

  beforeAll(async () => {
    userToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '15m' });
    adminToken = jwt.sign(adminPayload, JWT_SECRET, { expiresIn: '15m' });
    // Add a revoked token
    revokedJti = uuidv4();
    await prisma.revokedToken.create({
      data: {
        jti: revokedJti,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      },
    });
  });

  afterAll(async () => {
    await prisma.revokedToken.deleteMany({ where: { jti: revokedJti } });
    await prisma.$disconnect();
  });

  it('should reject missing token', async () => {
    const res = await request(app).get('/protected');
    expect(res.statusCode).toBe(401);
  });

  it('should reject invalid token', async () => {
    const res = await request(app).get('/protected').set('Authorization', 'Bearer invalidtoken');
    expect(res.statusCode).toBe(401);
  });

  it('should reject revoked token', async () => {
    const revokedToken = jwt.sign({ ...userPayload, jti: revokedJti }, JWT_SECRET, {
      expiresIn: '15m',
    });
    const res = await request(app).get('/protected').set('Authorization', `Bearer ${revokedToken}`);
    expect(res.statusCode).toBe(401);
  });

  it('should allow valid user token', async () => {
    const res = await request(app).get('/protected').set('Authorization', `Bearer ${userToken}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.user).toHaveProperty('username', 'user');
  });

  it('should allow admin to access admin route', async () => {
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.user).toHaveProperty('role', 'admin');
  });

  it('should forbid user from admin route', async () => {
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${userToken}`);
    expect(res.statusCode).toBe(403);
  });
});
