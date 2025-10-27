import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { Socket } from 'socket.io-client';
import { createTestApp } from './setup.e2e';
import { connectSocket } from './utils/test-client';
import { loginTestUser } from './utils/auth-helper';

describe('Realtime Gateway (e2e)', () => {
  let app: INestApplication;
  let socket: Socket;
  let cookieHeader: string;
  let url: string;

  beforeAll(async () => {
    app = await createTestApp();
    const server = app.getHttpServer();
    const address = server.address();
    const port = typeof address === 'object' ? address.port : 3001;
    url = `http://localhost:${port}/chat`;

    const login = await loginTestUser(app);
    cookieHeader = login.cookieHeader;
  });

  afterAll(async () => {
    if (socket?.connected) socket.disconnect();
    await app.close();
  });

  it('should connect with valid cookie', async () => {
    socket = await connectSocket(url, cookieHeader);
    expect(socket.connected).toBe(true);
  });

  it('should reject connection without cookie', async () => {
    await expect(connectSocket(url, '')).rejects.toBeDefined();
  });

  it('should join chat and send message', async () => {
    const chatId = '11111111-1111-4111-8111-111111111111';

    await new Promise<void>((resolve, reject) => {
      socket.emit('chat:join', { chatId });

      setTimeout(() => {
        socket.emit('message:send', { chatId, content: 'Hello world' });
      }, 200);

      socket.on('message:new', (msg) => {
        expect(msg.content).toBe('Hello world');
        expect(msg.chatId).toBe(chatId);
        resolve();
      });

      socket.on('connect_error', reject);
    });
  });

  it('should disconnect after session revoke', async () => {
    await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', cookieHeader)
      .expect(200);

    await new Promise((r) => setTimeout(r, 1500));
    expect(socket.connected).toBe(false);
  });
});
