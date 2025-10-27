// apps/backend/src/modules/auth/jwt/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '@/prisma/prisma.service';
import { AuthPayload } from '@szept/types';
import { AuthConfigService } from '@/config/auth.config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private prisma: PrismaService,
    private readonly cfg: AuthConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => req?.cookies?.access_token ?? null,
      ]),
      ignoreExpiration: false,
      secretOrKey: cfg.accessSecret,
      issuer: cfg.issuer,
      audience: cfg.audience,
    });
  }

  async validate(payload: AuthPayload) {
    const session = await this.prisma.refreshSession.findUnique({
      where: { id: payload.sessionId },
      select: { revokedAt: true, expiresAt: true },
    });

    if (!session) {
      throw new UnauthorizedException('Session not found');
    }

    if (session.revokedAt) {
      throw new UnauthorizedException('Session revoked');
    }

    if (session.expiresAt.getTime() <= Date.now()) {
      throw new UnauthorizedException('Session expired');
    }

    return {
      userId: payload.sub,
      sessionId: payload.sessionId,
      familyId: payload.familyId,
      roles: payload.role ?? ['user'],
    };
  }
}
