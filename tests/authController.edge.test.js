import request from 'supertest';
import app from '../server.js';

describe('Auth Controller Edge Cases', () => {
  it('should not register with short password', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'edgeuser', password: 'short' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error || res.body.errors).toBeDefined();
  });

  it('should not register with special chars in username', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ username: 'bad$user', password: 'TestPassword123!' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error || res.body.errors).toBeDefined();
  });

  it('should not refresh with invalid token', async () => {
    const res = await request(app).post('/auth/refresh').send({ refreshToken: 'not-a-token' });
    expect(res.statusCode).toBe(401);
  });

  it('should not logout with missing token', async () => {
    const res = await request(app).post('/auth/logout').send({});
    expect(res.statusCode).toBe(400);
  });
});
