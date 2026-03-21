import 'dotenv/config';
import path from 'path';
import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: path.join('prisma', 'schema.prisma'),
  datasource: {
    url: process.env.DATABASE_URL!,
  },
  migrate: {
    async adapter() {
      const { PrismaPg } = await import('@prisma/adapter-pg');
      return new PrismaPg({ connectionString: process.env.DATABASE_URL! });
    },
  },
});
