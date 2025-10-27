// apps\backend\src\modules\realtime\utils\chat.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { UseGuards, Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { ConfigService } from '@nestjs/config';
import { buildSocketAuthMiddleware } from '../socket-auth.middleware';
import { WsJwtGuard } from '../utils/ws-jwt.guard';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '@/modules/auth/auth.service';
import { EventEmitter2, OnEvent } from '@nestjs/event-emitter';

@WebSocketGateway({
  namespace: '/chat',
  transports: ['websocket'],
})
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server!: Server;
  private readonly logger = new Logger(ChatGateway.name);
  private static readonly MAX_USER_SOCKETS = 3;

  constructor(
    private readonly jwt: JwtService,
    private readonly auth: AuthService,
    private readonly config: ConfigService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  afterInit(server: Server): void {
    server.use(
      buildSocketAuthMiddleware(this.jwt, this.auth, {
        accessCookieName:
          this.config.get<string>('ACCESS_COOKIE_NAME') ?? 'access_token',
        jwtAudience: this.config.get<string>('JWT_AUDIENCE') ?? '',
        jwtIssuer: this.config.get<string>('JWT_ISSUER') ?? '',
      }),
    );
  }

  async handleConnection(socket: Socket) {
    const user = socket.data?.user;
    if (!user?.userId) {
      socket.disconnect(true);
      return;
    }

    const io = socket.nsp.server;
    const room = io.sockets.adapter.rooms.get(`user:${user.userId}`);
    if (room && room.size > ChatGateway.MAX_USER_SOCKETS) {
      this.logger.warn(`Too many sockets for user ${user.userId}`);
      socket.disconnect(true);
      return;
    }

    this.logger.log(`Connected user=${user.userId} sid=${socket.id}`);
    await this.auth.createSecurityEvent({
      userId: user.userId,
      type: 'SOCKET_CONNECT',
      ip: user.ip,
      ua: user.ua,
    });
  }

  async handleDisconnect(socket: Socket) {
    const user = socket.data?.user;
    if (user?.userId) {
      await this.auth.createSecurityEvent({
        userId: user.userId,
        type: 'SOCKET_DISCONNECT',
        ip: user.ip,
        ua: user.ua,
      });
      this.logger.log(`Disconnected user=${user.userId}`);
    }
  }

  @OnEvent('auth.session.revoked')
  onSessionRevoked(payload: { userId: string }) {
    this.logger.log(`Disconnecting sockets for user=${payload.userId}`);
    this.server.to(`user:${payload.userId}`).disconnectSockets(true);
  }

  @OnEvent('auth.session.revoked-all')
  onAllSessionsRevoked(payload: { userId: string }) {
    this.logger.log(`Disconnecting all sockets for user=${payload.userId}`);
    this.server.to(`user:${payload.userId}`).disconnectSockets(true);
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('ping')
  handlePing(client: Socket): String {
    return 'pong';
  }
}
