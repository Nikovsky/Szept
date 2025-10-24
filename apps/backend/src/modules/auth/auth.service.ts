import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '@/prisma/prisma.service';
import * as argon2 from 'argon2';
import { randomBytes, createHash, randomUUID, timingSafeEqual } from 'crypto';
import { addSeconds } from 'date-fns';
import { jwtConfig } from '@/config/jwt.config';
import { AccessPayload, SecurityEvent, TokenBundle } from '@szept/types';
import { LoginUserDto, RegisterUserDto } from './dto/auth.dto';
import { RefreshSession } from 'generated/prisma/client';

@Injectable()
export class AuthService {
  private readonly cfg = jwtConfig();
  private readonly logger = new Logger(AuthService.name);
  private readonly ipSalt = process.env.IP_HASH_SALT ?? 'ip-salt';
  private readonly uaSalt = process.env.UA_HASH_SALT ?? 'ua-salt';
  private readonly csrfSalt = process.env.CSRF_HASH_SALT ?? 'csrf-salt';
  private readonly MAX_SESSIONS = 3;
  private readonly REUSE =
    (process.env.ENABLE_SESSION_REUSE ?? 'false') === 'true';

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  // --- UTILS ---

  private sha256(value: string, salt: string): string {
    return createHash('sha256')
      .update(salt + '|' + value)
      .digest('base64url');
  }

  private genOpaque() {
    return randomBytes(32).toString('base64url');
  }
  private genCsrf() {
    return randomBytes(16).toString('base64url');
  }
  private csrfHash(t: string) {
    return this.sha256(t, this.csrfSalt);
  }

  private async signAccess(userId: string, sid: string) {
    const payload: AccessPayload = { sub: userId, sid };
    return this.jwt.signAsync(payload, {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: this.cfg.ACCESS_TTL,
      issuer: this.cfg.ISSUER,
      audience: this.cfg.AUDIENCE,
    });
  }

  private async logSecurity(event: SecurityEvent) {
    try {
      await this.prisma.securityEvent.create({
        data: {
          type: event.type,
          userId: event.userId,
          ip: event.ip ?? null,
          ua: event.ua ?? null,
          details: event.details ? JSON.stringify(event.details) : null,
        },
      });
    } catch (e: Error | any) {
      this.logger.warn(`Security log failed: ${e.message}`);
    }
  }

  // --- core logic ---
  async login(
    dto: LoginUserDto,
    ip?: string,
    ua?: string,
  ): Promise<TokenBundle> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      await this.logSecurity({
        type: 'LOGIN',
        userId: 'unknown',
        ip,
        ua,
        details: {
          email: dto.email,
          success: false,
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const valid = await argon2.verify(user.password, dto.password);
    if (!valid) {
      await this.logSecurity({
        type: 'LOGIN',
        userId: user.id,
        ip,
        ua,
        details: {
          success: false,
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.issueSessionForUser(user.id, ip, ua);

    await this.logSecurity({
      type: 'LOGIN',
      userId: user.id,
      ip,
      ua,
      details: {
        success: true,
      },
    });

    return tokens;
  }

  async register(
    dto: RegisterUserDto,
    ip?: string,
    ua?: string,
  ): Promise<
    { user: { id: string; email: string; displayName: string } } & TokenBundle
  > {
    const existing = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: dto.email }, { displayName: dto.displayName }],
      },
    });

    if (existing) {
      throw new ForbiddenException(
        'User with given email or display name already exists',
      );
    }

    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 2,
      parallelism: 1,
    });

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        displayName: dto.displayName,
        password: passwordHash,
      },
    });

    const tokens = await this.issueSessionForUser(user.id, ip, ua);

    return {
      user: { id: user.id, email: user.email, displayName: user.displayName },
      ...tokens,
    };
  }

  private async issueSessionForUser(
    userId: string,
    ip?: string,
    ua?: string,
  ): Promise<TokenBundle> {
    if (this.REUSE && (ip || ua)) {
      const ipH = ip ? this.sha256(ip, this.ipSalt) : null;
      const uaH = ua ? this.sha256(ua, this.uaSalt) : null;
      const existing = await this.prisma.refreshSession.findFirst({
        where: {
          userId,
          revokedAt: null,
          ...(ipH ? { ipHash: ipH } : {}),
          ...(uaH ? { uaHash: uaH } : {}),
        },
        orderBy: { createdAt: 'desc' },
      });

      if (existing) {
        return this.rotateRefreshToken(existing.id, existing, ip, ua);
      }
    }

    const activeCount = await this.prisma.refreshSession.count({
      where: { userId, revokedAt: null },
    });

    if (activeCount >= this.MAX_SESSIONS) {
      const oldest = await this.prisma.refreshSession.findFirst({
        where: { userId, revokedAt: null },
        orderBy: { createdAt: 'asc' },
      });

      if (oldest) {
        await this.prisma.refreshSession.update({
          where: { id: oldest.id },
          data: { revokedAt: new Date() },
        });
      }
    }

    const refreshPlain = this.genOpaque();
    const rtHash = await argon2.hash(refreshPlain, { type: argon2.argon2id });
    const csrf = this.genCsrf();
    const csrfHash = this.csrfHash(csrf);

    const familyId = randomUUID();

    const session = await this.prisma.refreshSession.create({
      data: {
        userId,
        rtHash,
        familyId,
        expiresAt: addSeconds(new Date(), this.cfg.REFRESH_TTL),
        ipHash: ip ? this.sha256(ip, this.ipSalt) : null,
        uaHash: ua ? this.sha256(ua, this.uaSalt) : null,
        csrfHash,
      },
    });

    const access = await this.signAccess(userId, session.id);

    return {
      access,
      refresh: `${session.id}.${refreshPlain}`,
      csrf,
      accessTtlSec: this.cfg.ACCESS_TTL,
      refreshTtlSec: this.cfg.REFRESH_TTL,
    };
  }

  private async rotateRefreshToken(
    sessionId: string,
    loaded?: RefreshSession,
    ip?: string,
    ua?: string,
  ): Promise<TokenBundle> {
    const session =
      loaded ??
      (await this.prisma.refreshSession.findUnique({
        where: { id: sessionId },
      }));
    if (!session) throw new UnauthorizedException('Session not found');

    const newPlain = this.genOpaque();
    const newHash = await argon2.hash(newPlain, { type: argon2.argon2id });
    const csrf = this.genCsrf();
    const csrfHash = this.csrfHash(csrf);

    const newSession = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT id FROM "RefreshSession" WHERE id = ${session.id} FOR UPDATE`;

      const fresh = await tx.refreshSession.findUnique({
        where: { id: session.id },
      });
      if (!fresh || fresh.revokedAt)
        throw new ForbiddenException('Concurrent refresh');

      await tx.refreshSession.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
      });

      return tx.refreshSession.create({
        data: {
          userId: session.userId,
          rtHash: newHash,
          familyId: session.familyId,
          expiresAt: addSeconds(new Date(), this.cfg.REFRESH_TTL),
          ipHash: session.ipHash ?? (ip ? this.sha256(ip, this.ipSalt) : null),
          uaHash: session.uaHash ?? (ua ? this.sha256(ua, this.uaSalt) : null),
          csrfHash,
        },
      });
    });

    const access = await this.signAccess(session.userId, newSession.id);

    return {
      access,
      refresh: `${newSession.id}.${newPlain}`,
      csrf,
      accessTtlSec: this.cfg.ACCESS_TTL,
      refreshTtlSec: this.cfg.REFRESH_TTL,
    };
  }

  async revokeSession(sessionId: string, userId: string): Promise<void> {
    await this.prisma.refreshSession.updateMany({
      where: { id: sessionId, userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.logSecurity({
      type: 'REVOKE',
      userId,
    });
  }

  async revokeAll(userId: string): Promise<void> {
    await this.prisma.refreshSession.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.logSecurity({
      type: 'REVOKE',
      userId,
      details: { scope: 'all' },
    });
  }

  private async revokeFamily(
    familyId: string,
    userId: string,
    event: SecurityEvent['type'],
  ): Promise<void> {
    await this.prisma.refreshSession.updateMany({
      where: { familyId, userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.logSecurity({ type: event, userId, details: { familyId } });
  }

  async refresh(
    raw: string,
    csrfToken: string,
    ip?: string,
    ua?: string,
  ): Promise<TokenBundle> {
    if (!raw || raw.length < 40 || raw.length > 500)
      throw new UnauthorizedException('Malformed token');

    const [sid, plain] = raw.split('.');
    if (!sid || !plain) throw new UnauthorizedException('Malformed refresh');

    const session = await this.prisma.refreshSession.findUnique({
      where: { id: sid },
    });
    if (!session || session.revokedAt || session.expiresAt <= new Date())
      throw new UnauthorizedException('Session invalid/expired');

    if (!csrfToken || !session.csrfHash)
      throw new ForbiddenException('CSRF required');
    const a = Buffer.from(this.csrfHash(csrfToken));
    const b = Buffer.from(session.csrfHash);
    if (a.length !== b.length || !timingSafeEqual(a, b))
      throw new ForbiddenException('Invalid CSRF token');

    const ok = await argon2.verify(session.rtHash, plain);
    if (!ok) {
      await this.revokeFamily(
        session.familyId,
        session.userId,
        'REPLAY_DETECTED',
      );
      throw new ForbiddenException('Replay detected');
    }

    if (
      ip &&
      session.ipHash &&
      session.ipHash !== this.sha256(ip, this.ipSalt)
    ) {
      await this.revokeFamily(
        session.familyId,
        session.userId,
        'REPLAY_DETECTED',
      );
      throw new ForbiddenException('Device mismatch (IP)');
    }
    if (
      ua &&
      session.uaHash &&
      session.uaHash !== this.sha256(ua, this.uaSalt)
    ) {
      await this.revokeFamily(
        session.familyId,
        session.userId,
        'REPLAY_DETECTED',
      );
      throw new ForbiddenException('Device mismatch (UA)');
    }

    return this.rotateRefreshToken(session.id, session, ip, ua);
  }
}
