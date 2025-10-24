import {
  Body,
  Controller,
  Post,
  Req,
  Res,
  HttpCode,
  UseGuards,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginUserDto, RegisterUserDto } from './dto/auth.dto';
import { setAuthCookies, clearAuthCookies } from './utils/cookies.util';
import { JwtAuthGuard } from './jwt/jwt.guard';
import { CsrfGuard } from './utils/csrf.guard';
import { Throttle } from '@nestjs/throttler';
import { AuthRequest } from '@szept/types';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  // --- Rejestracja ---
  @Post('register')
  @HttpCode(201)
  @Throttle({ default: { ttl: 60, limit: 3 } })
  async register(
    @Body() dto: RegisterUserDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, access, refresh, csrf, accessTtlSec, refreshTtlSec } =
      await this.auth.register(dto, req.ip, req.get('user-agent'));

    setAuthCookies(res, access, refresh, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
      csrf,
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
    const { access, refresh, csrf, accessTtlSec, refreshTtlSec } =
      await this.auth.login(dto, req.ip, req.get('user-agent'));

    setAuthCookies(res, access, refresh, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
      csrf,
      accessTtlSec,
      refreshTtlSec,
    });

    return { ok: true };
  }

  // --- Refresh ---
  @Post('refresh')
  @HttpCode(200)
  @UseGuards(CsrfGuard)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const raw = req.cookies?.refresh_token;
    const csrf = req.get('x-csrf-token') || '';

    const {
      access,
      refresh,
      csrf: newCsrf,
      accessTtlSec,
      refreshTtlSec,
    } = await this.auth.refresh(raw, csrf, req.ip, req.headers['user-agent']);

    setAuthCookies(res, access, refresh, {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.COOKIE_DOMAIN,
      csrf: newCsrf,
      accessTtlSec,
      refreshTtlSec,
    });

    return { ok: true };
  }

  // --- Wylogowanie ---
  @Post('logout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard, CsrfGuard)
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
  @UseGuards(JwtAuthGuard, CsrfGuard)
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
}
