import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma  = new PrismaClient({ adapter });

beforeAll(async () => {
  await prisma.$connect();
});

// Nettoyage après tous les tests du fichier
afterAll(async () => {
  await prisma.vulnerability.deleteMany();
  await prisma.report.deleteMany();
  await prisma.scanModuleResult.deleteMany();
  await prisma.scan.deleteMany();
  await prisma.user.deleteMany();
  await prisma.$disconnect();
});
