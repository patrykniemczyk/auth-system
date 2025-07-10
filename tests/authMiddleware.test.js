import request from 'supertest';
import jwt from 'jsonwebtoken';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { PrismaClient } from '@prisma/client';
import { authenticateToken, authorizeRoles } from '../src/middlewares/auth.js';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_ACCESS_SECRET;

// Create a test app with protected routes
const createTestApp = () => {
  const app = express();
  app.use(express.json());

  // Protected route that requires authentication
  app.get('/protected', authenticateToken, (req, res) => {
    res.json({ user: req.user });
  });

  // Admin-only route that requires authentication and admin role
  app.get('/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
    res.json({ user: req.user });
  });

  // Multi-role route for testing multiple roles
  app.get('/moderator', authenticateToken, authorizeRoles('admin', 'moderator'), (req, res) => {
    res.json({ user: req.user });
  });

  return app;
};

// Tests for auth middleware
describe('Auth Middleware', () => {
  let testApp;
  let userToken, adminToken, moderatorToken, revokedJti;

  const userPayload = { sub: 'user-id', username: 'user', role: 'user', jti: uuidv4() };
  const adminPayload = { sub: 'admin-id', username: 'admin', role: 'admin', jti: uuidv4() };
  const moderatorPayload = {
    sub: 'mod-id',
    username: 'moderator',
    role: 'moderator',
    jti: uuidv4(),
  };

  beforeAll(async () => {
    testApp = createTestApp();

    // Generate test tokens
    userToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '15m' });
    adminToken = jwt.sign(adminPayload, JWT_SECRET, { expiresIn: '15m' });
    moderatorToken = jwt.sign(moderatorPayload, JWT_SECRET, { expiresIn: '15m' });

    // Add a revoked token to database
    revokedJti = uuidv4();
    await prisma.revokedToken.create({
      data: {
        jti: revokedJti,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      },
    });
  });

  afterAll(async () => {
    // Clean up test data
    await prisma.revokedToken.deleteMany({ where: { jti: revokedJti } });
    await prisma.$disconnect();
  });

  describe('authenticateToken middleware', () => {
    it('should reject request with missing token', async () => {
      const res = await request(testApp).get('/protected');
      expect(res.statusCode).toBe(401);
    });

    it('should reject request with invalid token format', async () => {
      const res = await request(testApp).get('/protected').set('Authorization', 'InvalidFormat');
      expect(res.statusCode).toBe(401);
    });

    it('should reject request with invalid token', async () => {
      const res = await request(testApp)
        .get('/protected')
        .set('Authorization', 'Bearer invalidtoken');
      expect(res.statusCode).toBe(401);
    });

    it('should reject request with expired token', async () => {
      const expiredToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '-1m' });
      const res = await request(testApp)
        .get('/protected')
        .set('Authorization', `Bearer ${expiredToken}`);
      expect(res.statusCode).toBe(401);
    });

    it('should reject request with revoked token', async () => {
      const revokedToken = jwt.sign({ ...userPayload, jti: revokedJti }, JWT_SECRET, {
        expiresIn: '15m',
      });
      const res = await request(testApp)
        .get('/protected')
        .set('Authorization', `Bearer ${revokedToken}`);
      expect(res.statusCode).toBe(401);
    });

    it('should accept request with valid token', async () => {
      const res = await request(testApp)
        .get('/protected')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.statusCode).toBe(200);
      expect(res.body.user).toHaveProperty('username', 'user');
      expect(res.body.user).toHaveProperty('role', 'user');
      expect(res.body.user).toHaveProperty('sub', 'user-id');
    });
  });

  describe('authorizeRoles middleware', () => {
    it('should allow admin to access admin route', async () => {
      const res = await request(testApp).get('/admin').set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toBe(200);
      expect(res.body.user).toHaveProperty('role', 'admin');
    });

    it('should forbid user from accessing admin route', async () => {
      const res = await request(testApp).get('/admin').set('Authorization', `Bearer ${userToken}`);
      expect(res.statusCode).toBe(403);
    });

    it('should allow admin to access multi-role route', async () => {
      const res = await request(testApp)
        .get('/moderator')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toBe(200);
      expect(res.body.user).toHaveProperty('role', 'admin');
    });

    it('should allow moderator to access multi-role route', async () => {
      const res = await request(testApp)
        .get('/moderator')
        .set('Authorization', `Bearer ${moderatorToken}`);
      expect(res.statusCode).toBe(200);
      expect(res.body.user).toHaveProperty('role', 'moderator');
    });

    it('should forbid user from accessing multi-role route', async () => {
      const res = await request(testApp)
        .get('/moderator')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.statusCode).toBe(403);
    });
  });

  describe('middleware combination', () => {
    it('should handle missing authorization header gracefully', async () => {
      const res = await request(testApp).get('/admin');
      expect(res.statusCode).toBe(401);
    });

    it('should handle malformed authorization header', async () => {
      const res = await request(testApp).get('/admin').set('Authorization', 'Bearer');
      expect(res.statusCode).toBe(401);
    });

    it('should process valid token through both middlewares', async () => {
      const res = await request(testApp).get('/admin').set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toBe(200);
      expect(res.body.user).toMatchObject({
        username: 'admin',
        role: 'admin',
        sub: 'admin-id',
      });
    });
  });
});
