import * as argon2 from 'argon2';
import { PrismaClient } from '../../generated/prisma/client';
import 'dotenv/config';

const prisma = new PrismaClient();

async function main() {
  const passwordHash = await argon2.hash('Test1234!', {
    type: argon2.argon2id,
  });

  // --- Użytkownik testowy ---
  const user = await prisma.user.upsert({
    where: { email: 'user@example.com' },
    update: {},
    create: {
      id: '3756a781-6590-41f4-91fc-90f309f56e0c', // <- ten sam ID co w testach
      email: 'user@example.com',
      password: passwordHash,
      displayName: 'Test User',
      status: 'ONLINE',
    },
  });

  // --- Poprawny UUIDv4 dla czatu ---
  const chat = await prisma.chat.upsert({
    where: { id: '11111111-1111-4111-8111-111111111111' }, // <- poprawny format UUIDv4
    update: {},
    create: {
      id: '11111111-1111-4111-8111-111111111111',
      name: 'E2E Chat',
      isGroup: false,
    },
  });

  // --- Połączenie użytkownika z czatem ---
  await prisma.userOnChat.upsert({
    where: {
      userId_chatId: {
        userId: user.id,
        chatId: chat.id,
      },
    },
    update: {},
    create: {
      userId: user.id,
      chatId: chat.id,
      role: 'member',
    },
  });

  console.log('✅ Seed data created');
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
