import Redis from 'ioredis';
import { config } from '@/utils/config';

// maxRetriesPerRequest: null est OBLIGATOIRE pour BullMQ
export const redis = new Redis(config.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck:     false,
  lazyConnect:          true,
});

redis.on('error', (err) => {
  // Logge sans crasher le process
  console.error('[Redis] Erreur de connexion :', err.message);
});

redis.on('connect', () => {
  console.log('[Redis] Connecté à', config.REDIS_URL);
});

/**
 * Options de connexion pour BullMQ.
 * BullMQ embarque sa propre version d'ioredis — on passe un plain object
 * pour éviter le conflit de types entre les deux versions.
 */
function parsedRedisUrl(url: string) {
  const parsed = new URL(url);
  return {
    host:                 parsed.hostname || '127.0.0.1',
    port:                 parseInt(parsed.port || '6379', 10),
    maxRetriesPerRequest: null as null,
    enableReadyCheck:     false,
  };
}

export const bullmqConnection = parsedRedisUrl(config.REDIS_URL);
