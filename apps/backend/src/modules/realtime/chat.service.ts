import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { SendMessageDto } from './dto/message.dto';
import { fromB64u } from '@/modules/e2ee/util/b64';

@Injectable()
export class ChatService {
  constructor(private readonly prisma: PrismaService) {}

  async canAccessChat(userId: string, chatId: string): Promise<boolean> {
    const member = await this.prisma.userOnChat.findUnique({
      where: { userId_chatId: { userId, chatId } },
      select: { userId: true },
    });
    return !!member;
  }

  async saveMessage(userId: string, dto: SendMessageDto) {
    const canAccess = await this.canAccessChat(userId, dto.chatId);
    if (!canAccess) throw new ForbiddenException('Access denied');

    const message = await this.prisma.message.create({
      data: {
        chatId: dto.chatId,
        senderId: userId,
        senderDeviceId: dto.senderDeviceId,
        encType: dto.encType,
        ciphertext: fromB64u(dto.ciphertextB64),
        nonce: fromB64u(dto.nonceB64),
        ad: dto.adB64 ? fromB64u(dto.adB64) : undefined,
        ratchetCounter: dto.ratchetCounter,
        keyId: dto.keyId,
        status: 'sent',
      },
      select: {
        id: true,
        chatId: true,
        senderId: true,
        senderDeviceId: true,
        createdAt: true,
      },
    });

    return message;
  }

  async markMessageRead(userId: string, chatId: string, messageId: string) {
    const canAccess = await this.canAccessChat(userId, chatId);
    if (!canAccess) throw new ForbiddenException('Access denied');

    return this.prisma.messageRead.upsert({
      where: { userId_messageId: { userId, messageId } },
      update: { readAt: new Date() },
      create: { userId, messageId, readAt: new Date() },
    });
  }
}
