// apps/backend/src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { SocketIoAdapter } from './modules/realtime/socket-io.adapter';
import helmet from 'helmet';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug'],
    cors: {
      origin: process.env.FRONTEND_URL ?? 'http://localhost:3000',
      credentials: true, // wymagane przy cookie-based auth
      allowedHeaders: ['Content-Type', 'Authorization'], // ❌ usuń 'x-csrf-token'
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    },
  });

  const config = app.get(ConfigService);
  const port = config.get<number>('PORT') ?? 3001;
  const frontend =
    config.get<string>('FRONTEND_URL') ?? 'http://localhost:3000';

  // --- Secure Cookies & Proxy ---
  app.getHttpAdapter().getInstance().set('trust proxy', 1);
  app.use(cookieParser());

  // --- Helmet (HTTP hardening) ---
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"], // potrzebne dla SSR/hydration
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: [
            "'self'",
            frontend,
            'ws://localhost:3001',
            'wss://localhost:3001',
            'http://localhost:3001',
          ],
          frameAncestors: ["'none'"], // brak iframingu (clickjacking)
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginEmbedderPolicy: false, // kompatybilność z Next.js
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );

  // --- Validation & Transformation ---
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // --- WebSocket Adapter ---
  app.useWebSocketAdapter(new SocketIoAdapter(app));

  // --- Graceful shutdown ---
  app.enableShutdownHooks();

  await app.listen(port);
  console.log(`🚀 Backend running on port ${port}`);
}
bootstrap();
