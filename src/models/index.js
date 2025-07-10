import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
  log: ['query', 'error'],
});

export default prisma;

// Graceful shutdown helper for server.js
export async function disconnectPrisma() {
  await prisma.$disconnect();
}
