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
import {
  AuthPayload,
  SecurityEvent,
  SessionInfo,
  TokenBundle,
  SecurityEventType,
} from '@szept/types';
import { LoginUserDto, RegisterUserDto } from './dto/auth.dto';
import { RefreshSession } from 'generated/prisma/client';
import { AuthConfigService } from '@/config/auth.config';
import { humanTime, parseUserAgent } from './utils/session-info.util';
import { EventEmitter2 } from '@nestjs/event-emitter';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
    private readonly jwt: JwtService,
    private readonly cfg: AuthConfigService,
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

  private async signAccess(
    userId: string,
    sessionId: string,
    familyId: string,
  ) {
    const payload: AuthPayload = { sub: userId, sessionId, familyId };
    return this.jwt.signAsync(payload, {
      secret: this.cfg.accessSecret,
      expiresIn: this.cfg.accessTtl,
      issuer: this.cfg.issuer,
      audience: this.cfg.audience,
    });
  }

  private hashLogValue(value?: string | null): string | null {
    if (!value) return null;
    const globalSalt = this.cfg.ipSalt;
    return createHash('sha256')
      .update(globalSalt + '|' + value)
      .digest('base64url');
  }

  private async logSecurity(event: SecurityEvent): Promise<void> {
    try {
      await this.prisma.securityEvent.create({
        data: {
          type: String(event.type),
          userId: event.userId,
          ip: this.hashLogValue(event.ip),
          ua: this.hashLogValue(event.ua),
          details: event.details ? JSON.stringify(event.details) : null,
        },
      });
    } catch (e: Error | any) {
      this.logger.warn(`Security log failed: ${e.message}`);
    }
  }

  async createSecurityEvent(data: {
    userId: string;
    type: string;
    ip?: string;
    ua?: string;
    details?: string;
  }) {
    await this.prisma.securityEvent.create({
      data: {
        userId: data.userId,
        type: data.type,
        ip: this.hashLogValue(data.ip),
        ua: this.hashLogValue(data.ua),
        details: data.details,
      },
    });
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
        type: SecurityEventType.LOGIN,
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
        type: SecurityEventType.LOGIN,
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
      type: SecurityEventType.LOGIN,
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
      memoryCost: this.cfg.argonMemory,
      timeCost: this.cfg.argonTime,
      parallelism: this.cfg.argonParallelism,
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
    const reuse = this.cfg.reuse;
    const ipSalt = this.cfg.ipSalt;
    const uaSalt = this.cfg.uaSalt;
    const maxSessions = this.cfg.maxSessions;

    if (reuse && (ip || ua)) {
      const ipH = ip ? this.sha256(ip, ipSalt) : null;
      const uaH = ua ? this.sha256(ua, uaSalt) : null;
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
        const access = await this.signAccess(
          userId,
          existing.id,
          existing.familyId,
        );

        const refresh = `${existing.id}.${this.genOpaque()}`; // nie rotuj w tym momencie
        return {
          access,
          refresh,
          accessTtlSec: this.cfg.accessTtl,
          refreshTtlSec: this.cfg.refreshTtl,
        };
      }
    }

    const activeCount = await this.prisma.refreshSession.count({
      where: { userId, revokedAt: null },
    });

    if (activeCount >= maxSessions) {
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

    const familyId = randomUUID();

    const session = await this.prisma.refreshSession.create({
      data: {
        userId,
        rtHash,
        familyId,
        expiresAt: addSeconds(new Date(), this.cfg.refreshTtl),
        ipHash: ip ? this.sha256(ip, ipSalt) : null,
        uaHash: ua ? this.sha256(ua, uaSalt) : null,
        refreshCount: 0,
      },
    });

    const access = await this.signAccess(userId, session.id, session.familyId);
    const refresh = `${session.id}.${refreshPlain}`;

    return {
      access,
      refresh,
      accessTtlSec: this.cfg.accessTtl,
      refreshTtlSec: this.cfg.refreshTtl,
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

    // Tworzymy nową sesję najpierw, potem unieważniamy starą
    const created = await this.prisma.$transaction(async (tx) => {
      const fresh = await tx.refreshSession.findUnique({
        where: { id: session.id },
      });

      if (!fresh || fresh.revokedAt)
        throw new ForbiddenException('Concurrent refresh');

      const newSession = await tx.refreshSession.create({
        data: {
          userId: session.userId,
          rtHash: newHash,
          familyId: session.familyId,
          expiresAt: addSeconds(new Date(), this.cfg.refreshTtl),
          ipHash:
            session.ipHash ?? (ip ? this.sha256(ip, this.cfg.ipSalt) : null),
          uaHash:
            session.uaHash ?? (ua ? this.sha256(ua, this.cfg.uaSalt) : null),
          refreshCount: session.refreshCount + 1,
        },
      });

      await tx.refreshSession.update({
        where: { id: session.id },
        data: { revokedAt: new Date(), lastUsedAt: new Date() },
      });

      return newSession;
    });

    const access = await this.signAccess(
      session.userId,
      created.id,
      created.familyId,
    );
    const refresh = `${created.id}.${newPlain}`;

    return {
      access,
      refresh,
      accessTtlSec: this.cfg.accessTtl,
      refreshTtlSec: this.cfg.refreshTtl,
    };
  }

  async revokeSession(sessionId: string, userId: string): Promise<void> {
    await this.prisma.refreshSession.updateMany({
      where: { id: sessionId, userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.eventEmitter.emit('auth.session.revoked', { userId, sessionId });
    await this.logSecurity({
      type: SecurityEventType.REVOKE,
      userId,
    });
  }

  async revokeAll(userId: string): Promise<void> {
    await this.prisma.refreshSession.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    this.eventEmitter.emit('auth.session.revoked-all', { userId });

    await this.logSecurity({
      type: SecurityEventType.REVOKE,
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

  async refresh(raw: string, ip?: string, ua?: string): Promise<TokenBundle> {
    if (!raw || raw.length < 10 || raw.length > 1000)
      throw new UnauthorizedException('Malformed token');

    const [sid, plain] = raw.split('.');
    if (!sid || !plain)
      throw new UnauthorizedException('Malformed refresh token');

    // szukaj tylko aktywnej sesji
    const session = await this.prisma.refreshSession.findFirst({
      where: { id: sid, revokedAt: null },
    });

    if (!session)
      throw new UnauthorizedException('Session not found or revoked');

    if (session.expiresAt <= new Date())
      throw new UnauthorizedException('Session expired');

    const ok = await argon2.verify(session.rtHash, plain);
    if (!ok) {
      await this.revokeFamily(
        session.familyId,
        session.userId,
        SecurityEventType.REPLAY_DETECTED,
      );
      throw new ForbiddenException('Replay detected');
    }

    // fingerprint validation (opcjonalna)
    if (
      ip &&
      session.ipHash &&
      session.ipHash !== this.sha256(ip, this.cfg.ipSalt)
    ) {
      await this.revokeFamily(
        session.familyId,
        session.userId,
        SecurityEventType.REPLAY_DETECTED,
      );
      throw new ForbiddenException('Device mismatch (IP)');
    }

    if (
      ua &&
      session.uaHash &&
      session.uaHash !== this.sha256(ua, this.cfg.uaSalt)
    ) {
      await this.revokeFamily(
        session.familyId,
        session.userId,
        SecurityEventType.REPLAY_DETECTED,
      );
      throw new ForbiddenException('Device mismatch (UA)');
    }

    return this.rotateRefreshToken(session.id, session, ip, ua);
  }

  async listUserSessions(userId: string): Promise<SessionInfo[]> {
    const sessions = await this.prisma.refreshSession.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        familyId: true,
        createdAt: true,
        lastUsedAt: true,
        expiresAt: true,
        revokedAt: true,
        ipHash: true,
        uaHash: true,
      },
    });
    return sessions.map((s) => {
      const parsed = parseUserAgent(s.uaHash ?? 'Unknown');

      return {
        id: s.id,
        familyId: s.familyId,
        createdAt: s.createdAt.toISOString(),
        lastUsedAt: s.lastUsedAt ? s.lastUsedAt.toISOString() : null,
        expiresAt: s.expiresAt.toISOString(),
        ipHash: s.ipHash,
        uaHash: s.uaHash,
        active: !s.revokedAt && s.expiresAt > new Date(),
        device: `${parsed.browser} / ${parsed.os}`,
        lastUsedHuman: humanTime(s.lastUsedAt || s.createdAt),
      };
    });
  }

  async revokeFamilySessions(
    userId: string,
    familyId: string,
  ): Promise<{ revoked: number }> {
    const result = await this.prisma.refreshSession.updateMany({
      where: { userId, familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.logSecurity({
      type: SecurityEventType.REVOKE,
      userId,
      details: { scope: 'family', familyId },
    });
    return { revoked: result.count };
  }

  async getSession(sessionId: string) {
    return this.prisma.refreshSession.findUnique({ where: { id: sessionId } });
  }

  async validateAccessSession(
    payload: AuthPayload,
    meta: { ip?: string; ua?: string },
  ): Promise<boolean> {
    const session = await this.prisma.refreshSession.findUnique({
      where: { id: payload.sessionId },
    });

    if (
      !session ||
      session.revokedAt ||
      session.expiresAt.getTime() <= Date.now()
    ) {
      return false;
    }

    if (meta.ip && session.ipHash) {
      const ipHash = this.sha256(meta.ip, this.cfg.ipSalt);
      if (ipHash !== session.ipHash) return false;
    }

    if (meta.ua && session.uaHash) {
      const uaHash = this.sha256(meta.ua, this.cfg.uaSalt);
      if (uaHash !== session.uaHash) return false;
    }

    return true;
  }
}
