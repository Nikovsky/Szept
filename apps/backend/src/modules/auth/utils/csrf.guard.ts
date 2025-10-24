import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { timingSafeEqual, createHash } from 'crypto';
import { AuthRequest } from '@szept/types';

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private prisma: PrismaService) {}
  private sha256(value: string, salt: string) {
    return createHash('sha256')
      .update(salt + '|' + value)
      .digest('base64url');
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<AuthRequest>();
    const method = req.method.toUpperCase();
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return true;

    const csrfHeader = req.get('x-csrf-token');
    const sid = req.user?.sessionId;
    if (!csrfHeader || !sid) throw new ForbiddenException('CSRF');

    const session = await this.prisma.refreshSession.findUnique({
      where: { id: sid },
    });

    if (!session || !session.csrfHash) throw new ForbiddenException('CSRF');

    const a = Buffer.from(
      this.sha256(csrfHeader, process.env.CSRF_HASH_SALT ?? 'csrf-salt'),
    );
    const b = Buffer.from(session.csrfHash);
    if (a.length !== b.length || !timingSafeEqual(a, b))
      throw new ForbiddenException('CSRF token invalid');

    return true;
  }
}
