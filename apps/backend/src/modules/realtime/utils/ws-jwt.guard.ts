// apps/backend/src/modules/realtime/utils/ws-jwt.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { WsException } from '@nestjs/websockets';

@Injectable()
export class WsJwtGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const client = ctx.switchToWs().getClient();
    if (!client?.data?.user?.userId) throw new WsException('Unauthorized!');
    return true;
  }
}
