// apps/backend/src/realtime/socket-auth.middleware.ts
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '../auth/auth.service';
import { parse as parseCookie } from 'cookie';
import { UnauthorizedException } from '@nestjs/common';
import type { Socket } from 'socket.io';
import { AuthPayload } from '@szept/types';

export function buildSocketAuthMiddleware(
  jwt: JwtService,
  auth: AuthService,
  opts: { accessCookieName: string; jwtAudience: string; jwtIssuer: string },
) {
  return async (socket: Socket, next: (err?: Error) => void) => {
    try {
      const rawCookie = socket.handshake.headers.cookie ?? '';
      const cookies = parseCookie(rawCookie);
      const token = cookies[opts.accessCookieName];

      if (!token) throw new UnauthorizedException('No acces token');

      const payload = await jwt.verifyAsync<AuthPayload>(token, {
        secret: process.env.JWT_ACCESS_SECRET,
        audience: opts.jwtAudience,
        issuer: opts.jwtIssuer,
      });

      const xff = socket.handshake.headers['x-forwarded-for'];
      const ip =
        (typeof xff === 'string' && xff.split(',')[0].trim()) ||
        socket.handshake.address.replace('::ffff:', '');
      const ua = socket.handshake.headers['user-agent'] ?? 'unknown';

      const ok = await auth.validateAccessSession(payload, { ip, ua });
      if (!ok) throw new UnauthorizedException('Session revoked');

      socket.data.user = {
        userId: payload.sub,
        roles: payload.role ?? [],
        sessionId: payload.sessionId,
        ip,
        ua,
      };

      socket.join(`user:${payload.sub}`);
      return next();
    } catch (e) {
      return next(e instanceof Error ? e : new Error('Unauthorized!'));
    }
  };
}
