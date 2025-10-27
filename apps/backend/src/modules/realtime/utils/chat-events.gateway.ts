import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import { UseGuards, Logger, ForbiddenException } from '@nestjs/common';
import { WsJwtGuard } from './ws-jwt.guard';
import { ChatService } from '../chat.service';
import {
  SendMessageDto,
  ReadMessageDto,
  JoinChatDto,
  TypingDto,
} from '../dto/message.dto';
import { plainToInstance } from 'class-transformer';
import { validateOrReject } from 'class-validator';
import { AuthService } from '@/modules/auth/auth.service';
import { Socket, Server } from 'socket.io';

@WebSocketGateway({
  namespace: '/chat',
  transports: ['websocket'],
})
export class ChatEventsGateway {
  @WebSocketServer() server!: Server;
  private readonly logger = new Logger(ChatEventsGateway.name);

  constructor(
    private readonly chatService: ChatService,
    private readonly auth: AuthService,
  ) {}

  // === EVENT: JOIN CHAT ===
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('chat:join')
  async joinChat(
    @ConnectedSocket() socket: Socket,
    @MessageBody() body: JoinChatDto,
  ) {
    await validateOrReject(plainToInstance(JoinChatDto, body));
    const userId = socket.data.user.userId;

    const canAccess = await this.chatService.canAccessChat(userId, body.chatId);
    if (!canAccess) throw new ForbiddenException('Access denied');

    socket.join(`room:${body.chatId}`);
    this.logger.log(`User ${userId} joined chat ${body.chatId}`);

    await this.auth.createSecurityEvent({
      userId,
      type: 'CHAT_JOIN',
      ip: socket.data.user.ip,
      ua: socket.data.user.ua,
      details: JSON.stringify({ chatId: body.chatId }),
    });

    return { ok: true };
  }

  // === EVENT: SEND MESSAGE ===
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('message:send')
  async sendMessage(
    @ConnectedSocket() socket: Socket,
    @MessageBody() body: SendMessageDto,
  ) {
    await validateOrReject(plainToInstance(SendMessageDto, body));
    const userId = socket.data.user.userId;

    const saved = await this.chatService.saveMessage(userId, body);

    this.server.in(`room:${body.chatId}`).emit('message:new', {
      id: saved.id,
      chatId: saved.chatId,
      senderId: saved.senderId,
      senderDeviceId: body.senderDeviceId,
      encType: body.encType,
      ciphertextB64: body.ciphertextB64,
      nonceB64: body.nonceB64,
      adB64: body.adB64,
      ratchetCounter: body.ratchetCounter,
      keyId: body.keyId,
      createdAt: saved.createdAt,
    });

    await this.auth.createSecurityEvent({
      userId,
      type: 'MESSAGE_SEND',
      ip: socket.data.user.ip,
      ua: socket.data.user.ua,
      details: JSON.stringify({ chatId: body.chatId }),
    });

    return { ok: true };
  }

  // === EVENT: READ MESSAGE ===
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('message:read')
  async markMessageRead(
    @ConnectedSocket() socket: Socket,
    @MessageBody() body: ReadMessageDto,
  ) {
    await validateOrReject(plainToInstance(ReadMessageDto, body));
    const userId = socket.data.user.userId;

    await this.chatService.markMessageRead(userId, body.chatId, body.messageId);

    this.server.to(`room:${body.chatId}`).emit('message:read', {
      userId,
      messageId: body.messageId,
    });

    await this.auth.createSecurityEvent({
      userId,
      type: 'MESSAGE_READ',
      ip: socket.data.user.ip,
      ua: socket.data.user.ua,
      details: JSON.stringify({
        chatId: body.chatId,
        messageId: body.messageId,
      }),
    });

    return { ok: true };
  }

  // === EVENT: USER TYPING ===
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('user:typing')
  async userTyping(
    @ConnectedSocket() socket: Socket,
    @MessageBody() body: TypingDto,
  ) {
    await validateOrReject(plainToInstance(TypingDto, body));
    const userId = socket.data.user.userId;

    const canAccess = await this.chatService.canAccessChat(userId, body.chatId);
    if (!canAccess) throw new ForbiddenException('Access denied');

    this.server.to(`room:${body.chatId}`).emit('user:typing', {
      userId,
      chatId: body.chatId,
      ts: Date.now(),
    });

    return { ok: true };
  }
}
