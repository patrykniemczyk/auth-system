// Tests for authController
import request from 'supertest';
import app from '../server.js';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

describe('Auth Controller', () => {
  const testUser = {
    username: `testuser_${Date.now()}`,
    password: 'TestPassword123!',
  };
  let refreshToken;

  afterAll(async () => {
    // Clean up test user and tokens
    await prisma.refreshToken.deleteMany({ where: { user: { username: testUser.username } } });
    await prisma.user.deleteMany({ where: { username: testUser.username } });
    await prisma.$disconnect();
  });

  it('should register a new user', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: testUser.username, password: testUser.password });
    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('username', testUser.username);
  });

  it('should login a user', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: testUser.username, password: testUser.password });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    refreshToken = res.body.refreshToken;
  });

  it('should refresh token', async () => {
    const res = await request(app).post('/auth/refresh').send({ refreshToken });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
  });

  it('should logout user', async () => {
    const res = await request(app).post('/auth/logout').send({ refreshToken });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message');
  });
});
