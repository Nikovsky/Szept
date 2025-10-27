// apps/backend/src/modules/realtime/socket-io.adapter.ts
import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IoAdapter } from '@nestjs/platform-socket.io';
import type { ServerOptions } from 'socket.io';

export class SocketIoAdapter extends IoAdapter {
  constructor(private app: INestApplication) {
    super(app);
  }

  createIOServer(port: number, options?: ServerOptions) {
    const config = this.app.get(ConfigService);

    const origins = (config.get<string>('SOCKET_ORIGINS') ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    const path = config.get<string>('SOCKET_PATH') ?? '/socket.io';

    const server = super.createIOServer(port, {
      path,
      cors: {
        origin: (origin, cb) => {
          if (!origin) return cb(new Error('Origin required'), false);
          if (origins.includes(origin)) return cb(null, true);
          return cb(new Error('Origin not allowe'), false);
        },
        credentials: true,
      },
      allowRequest: (req, callback) => {
        const origin = req.headers.origin as string | undefined;
        if (!origin || !origins.includes(origin)) {
          return callback('Forbidden', false);
        }
        const raw = req.headers.cookie ?? '';
        const hasCookie = raw.includes(
          (config.get<string>('ACCESS_COOKIE_NAME') ?? 'access_token') + '=',
        );
        if (!hasCookie) return callback('Unauthorized', false);
        callback(null, true);
      },
      transports: ['websocket'],
      allowEIO3: false,
      perMessageDeflate: false,
      maxHttpBufferSize: 100_00,
      pingTimeout: 15_000,
      pingInterval: 20_000,
      connectTimeout: 5_000,
      httpCompressiom: false,
      ...options,
    });

    return server;
  }
}
