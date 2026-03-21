import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL:  z.string().min(1),
  REDIS_URL:     z.string().min(1),
  JWT_SECRET:    z.string().min(32),
  JWT_EXPIRES_IN:z.string().default('24h'),
  PORT:          z.string().default('3001'),
  NODE_ENV:      z.enum(['development', 'production', 'test']).default('development'),
  SCANNER_PATH:  z.string().default('../scanner'),
  REPORTS_PATH:  z.string().default('./reports'),
  FRONTEND_URL:  z.string().default('http://localhost:5173'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("❌ Variables d'environnement invalides :");
  console.error(parsed.error.format());
  process.exit(1);
}

export const config = parsed.data;
