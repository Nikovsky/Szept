import request from 'supertest';
import { INestApplication } from '@nestjs/common';

export const TEST_UA = 'jest-e2e';
export const TEST_IP = '127.0.0.1';

export async function loginTestUser(app: INestApplication) {
  const res = await request(app.getHttpServer())
    .post('/auth/login')
    .send({ email: 'user@example.com', password: 'Test1234!' })
    .expect(200);

  const rawCookies = res.headers['set-cookie'];
  const cookies = Array.isArray(rawCookies)
    ? rawCookies
    : [rawCookies].filter(Boolean);

  const access = cookies.find((c) => c.includes('access_token'));
  const refresh = cookies.find((c) => c.includes('refresh_token'));

  return {
    cookieHeader: cookies.join('; '),
    accessToken: access,
    refreshToken: refresh,
  };
}
