// apps/backend/src/modules/auth/auth.constroller.ts
import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  HttpCode,
  UseGuards,
  Param,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginUserDto, RegisterUserDto } from './dto/auth.dto';
import { setAuthCookies, clearAuthCookies } from './utils/cookies.util';
import { JwtAuthGuard } from './jwt/jwt.guard';
import { Throttle } from '@nestjs/throttler';
import { AuthRequest, SessionInfo } from '@szept/types';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  private extractClientInfo(req: Request) {
    const ipHeader = req.headers['x-forwarded-for'] as string | undefined;
    const ip =
      ipHeader?.split(',')[0].trim() ??
      req.socket?.remoteAddress?.replace('::ffff:', '') ??
      (req.ip ?? '').replace('::ffff:', '');
    const ua = req.headers['user-agent'] ?? '';
    return { ip, ua };
  }

  // --- Rejestracja ---
  @Post('register')
  @HttpCode(201)
  @Throttle({ default: { ttl: 60, limit: 3 } })
  async register(
    @Body() dto: RegisterUserDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { ip, ua } = this.extractClientInfo(req);

    const { user, access, refresh, accessTtlSec, refreshTtlSec } =
      await this.auth.register(dto, ip, ua);

    setAuthCookies(res, access, refresh, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
      accessTtlSec,
      refreshTtlSec,
    });

    return { user, ok: true };
  }

  // --- Logowanie ---
  @Post('login')
  @HttpCode(200)
  @Throttle({ default: { ttl: 60, limit: 5 } })
  async login(
    @Body() dto: LoginUserDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { ip, ua } = this.extractClientInfo(req);

    const { access, refresh, accessTtlSec, refreshTtlSec } =
      await this.auth.login(dto, ip, ua);

    setAuthCookies(res, access, refresh, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
      accessTtlSec,
      refreshTtlSec,
    });

    return { ok: true };
  }

  // --- Refresh ---
  @Post('refresh')
  @HttpCode(200)
  @Throttle({ default: { ttl: 30, limit: 10 } })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { ip, ua } = this.extractClientInfo(req);
    const raw = req.cookies?.refresh_token;

    const { access, refresh, accessTtlSec, refreshTtlSec } =
      await this.auth.refresh(raw, ip, ua);

    setAuthCookies(res, access, refresh, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
      accessTtlSec,
      refreshTtlSec,
    });

    return { ok: true };
  }

  // --- Wylogowanie ---
  @Post('logout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async logout(
    @Req() req: AuthRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.auth.revokeSession(req.user.sessionId, req.user.userId);
    clearAuthCookies(res, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
    });

    return { ok: true };
  }

  @Post('logout-all')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async logoutAll(
    @Req() req: AuthRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.auth.revokeAll(req.user.userId);

    clearAuthCookies(res, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
    });

    return { ok: true };
  }

  // --- Lista sesji ---
  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async listSessions(
    @Req() req: AuthRequest,
  ): Promise<{ sessions: SessionInfo[] }> {
    const sessions = await this.auth.listUserSessions(req.user.userId);
    return { sessions };
  }

  // --- UNIEWAŻNIANIE FAMILY ---
  @Post('revoke-family/:familyId')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async revokeFamily(
    @Req() req: AuthRequest,
    @Param('familyId') familyId: string,
  ): Promise<{ revoked: number }> {
    return this.auth.revokeFamilySessions(req.user.userId, familyId);
  }
}
