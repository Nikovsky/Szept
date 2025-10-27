// apps/backend/src/modules/realtime/realtime.module.ts
import { Module } from '@nestjs/common';
import { ChatGateway } from './utils/chat.gateway';
import { WsJwtGuard } from './utils/ws-jwt.guard';
import { AuthModule } from '../auth/auth.module';
import { ChatEventsGateway } from './utils/chat-events.gateway';
import { ChatService } from './chat.service';
import { PrismaModule } from '@/prisma/prisma.module';

@Module({
  imports: [AuthModule, PrismaModule],
  providers: [ChatGateway, WsJwtGuard, ChatEventsGateway, ChatService],
  exports: [],
})
export class RealtimeModule {}
