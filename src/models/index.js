import { PrismaClient } from '@prisma/client';

/**
 * Prisma client instance for DB access
 * @type {import('@prisma/client').PrismaClient}
 */
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
  log: ['query', 'error'],
});

export default prisma;

/**
 * Gracefully disconnects Prisma client
 */
export async function disconnectPrisma() {
  await prisma.$disconnect();
}
