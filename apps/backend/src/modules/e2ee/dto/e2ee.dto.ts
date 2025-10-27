import {
  IsArray,
  IsInt,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class PreKeyItemDto {
  @IsInt() @Min(1) keyId!: number;
  @IsString() pubB64!: string; // base64url
}

export class OneTimeBatchDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PreKeyItemDto)
  items!: PreKeyItemDto[];
}

export class SignedPreKeyDto extends PreKeyItemDto {
  @IsString() signatureB64!: string;
}

export class RegisterDeviceDto {
  @IsString() name!: string;
  @IsString() platform!: string; // enforce enum w warstwie domeny
  @IsString() idKeyPubB64!: string; // X25519 pub
  @IsString() signKeyPubB64!: string; // Ed25519 pub
  @ValidateNested()
  @Type(() => SignedPreKeyDto)
  signedPreKey!: SignedPreKeyDto;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PreKeyItemDto)
  oneTime?: PreKeyItemDto[];
}

export class VerifyDeviceDto {
  @IsString()
  fingerprint!: string;

  @IsString()
  method!: string;
}
