// apps/backend/src/modules/realtime/dto/message.dto.ts
import {
  IsIBAN,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Length,
  Min,
} from 'class-validator';

export class SendMessageDto {
  @IsUUID()
  chatId!: string;

  @IsUUID()
  senderDeviceId!: string;

  @IsString()
  encType!: string;

  @IsString()
  ciphertextB64!: string;

  @IsString()
  nonceB64!: string;

  @IsOptional()
  @IsString()
  adB64!: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  ratchetCounter?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  keyId?: number;
}

export class ReadMessageDto {
  @IsUUID()
  chatId!: string;

  @IsUUID()
  messageId!: string;
}

export class JoinChatDto {
  @IsUUID()
  chatId!: string;
}

export class TypingDto {
  @IsUUID()
  chatId!: string;
}
