import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

describe('POST /api/auth/register', () => {
  it('201 — crée un compte et retourne un token', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'testuser', email: 'test@vulnscan.io', password: 'Test@2026' });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.token).toBeDefined();
    expect(res.body.data.user.email).toBe('test@vulnscan.io');
    expect(res.body.data.user.passwordHash).toBeUndefined();
  });

  it('422 — champs manquants', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'bad' });

    expect(res.status).toBe(422);
    expect(res.body.success).toBe(false);
  });

  it('409 — email déjà utilisé', async () => {
    await request(app).post('/api/auth/register')
      .send({ username: 'alice', email: 'alice@vulnscan.io', password: 'Alice@2026' });

    const res = await request(app).post('/api/auth/register')
      .send({ username: 'alice2', email: 'alice@vulnscan.io', password: 'Alice@2026' });

    expect(res.status).toBe(409);
  });
});

describe('POST /api/auth/login', () => {
  beforeAll(async () => {
    await request(app).post('/api/auth/register')
      .send({ username: 'loginuser', email: 'login@vulnscan.io', password: 'Login@2026' });
  });

  it('200 — connexion réussie', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@vulnscan.io', password: 'Login@2026' });

    expect(res.status).toBe(200);
    expect(res.body.data.token).toBeDefined();
  });

  it('401 — mauvais mot de passe', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@vulnscan.io', password: 'wrongpass' });

    expect(res.status).toBe(401);
  });
});

describe('GET /api/auth/me', () => {
  it('401 — sans token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('200 — avec token valide', async () => {
    const reg = await request(app).post('/api/auth/register')
      .send({ username: 'meuser', email: 'me@vulnscan.io', password: 'Me@12345A' });
    const token = reg.body.data.token;

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data.email).toBe('me@vulnscan.io');
  });
});
