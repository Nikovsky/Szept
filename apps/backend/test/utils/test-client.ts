import { io, Socket } from 'socket.io-client';
import { TEST_IP, TEST_UA } from './auth-helper';

export async function connectSocket(
  url: string,
  cookieHeader: string,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = io(url, {
      withCredentials: true,
      transports: ['websocket'],
      extraHeaders: {
        cookie: cookieHeader,
        'user-agent': TEST_UA,
        'x-forwarded-for': TEST_IP,
      },
    });

    socket.on('connect', () => resolve(socket));
    socket.on('connect_error', (err) => reject(err));
  });
}
