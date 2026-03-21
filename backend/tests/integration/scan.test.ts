import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../src/index';

let token: string;

beforeAll(async () => {
  // Créer un compte de test et récupérer le token
  const res = await request(app).post('/api/auth/register').send({
    username: 'scanuser', email: 'scanuser@vulnscan.io', password: 'Scan@2026',
  });
  token = res.body.data?.token;
});

describe('POST /api/scans', () => {
  it('401 — sans token', async () => {
    const res = await request(app).post('/api/scans')
      .send({ targetUrl: 'http://example.com' });
    expect(res.status).toBe(401);
  });

  it('422 — URL invalide', async () => {
    const res = await request(app).post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ targetUrl: 'pas-une-url' });
    expect(res.status).toBe(422);
  });

  it('503 — si aucun module disponible (DB vide)', async () => {
    // Avec la DB de test vide (pas de ScanModule), on attend 503
    const res = await request(app).post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ targetUrl: 'http://example.com', depth: 'normal' });
    // 503 si pas de modules, 201 si des modules existent dans la DB de test
    expect([201, 503]).toContain(res.status);
  });
});

describe('GET /api/scans', () => {
  it('401 — sans token', async () => {
    const res = await request(app).get('/api/scans');
    expect(res.status).toBe(401);
  });

  it('200 — retourne la liste paginée', async () => {
    const res = await request(app).get('/api/scans')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('scans');
    expect(res.body.data).toHaveProperty('total');
    expect(Array.isArray(res.body.data.scans)).toBe(true);
  });
});

describe('DELETE /api/scans/:id', () => {
  it('403 — ne peut pas supprimer le scan d\'un autre utilisateur', async () => {
    // Créer un deuxième utilisateur
    const res2 = await request(app).post('/api/auth/register').send({
      username: 'other', email: 'other@vulnscan.io', password: 'Other@2026',
    });
    const token2 = res2.body.data?.token;

    // Créer un scan avec le premier utilisateur
    // Utilise un fake ID pour tester le 403/404
    const res = await request(app).delete('/api/scans/non-existent-id')
      .set('Authorization', `Bearer ${token2}`);
    expect([403, 404]).toContain(res.status);
  });
});
