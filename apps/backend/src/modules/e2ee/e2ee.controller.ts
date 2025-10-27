import {
  Body,
  Controller,
  NotFoundException,
  Get,
  Post,
  Param,
  Req,
  UnauthorizedException,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { JwtAuthGuard } from '@/modules/auth/jwt/jwt.guard';
import { E2eeService } from './e2ee.service';
import {
  OneTimeBatchDto,
  RegisterDeviceDto,
  SignedPreKeyDto,
  VerifyDeviceDto,
} from './dto/e2ee.dto';
import { Request } from 'express';

@UseGuards(JwtAuthGuard)
@Controller('e2ee')
export class E2eeController {
  constructor(private readonly svc: E2eeService) {}

  @Post('devices/register')
  async register(@Body() dto: RegisterDeviceDto, @Req() req: Request) {
    const user = req.user as { userId?: string };
    if (!user?.userId) {
      throw new UnauthorizedException('Missing userId in request');
    }
    return this.svc.registerDevice(user.userId, dto);
  }

  @Get('devices/:deviceId/bundle')
  async getBundle(@Param('deviceId') deviceId: string) {
    const bundle = await this.svc.issueBundle(deviceId);
    if (!bundle) throw new NotFoundException('device not found');
    return bundle;
  }

  @Post('devices/:deviceId/prekeys/one-time')
  async uploadOneTime(
    @Param('deviceId') deviceId: string,
    @Body() dto: OneTimeBatchDto,
  ) {
    return this.svc.uploadOneTime(deviceId, dto);
  }

  @Post('devices/:deviceId/prekeys/signed')
  async rotateSigned(
    @Param('deviceId') deviceId: string,
    @Body() dto: SignedPreKeyDto,
  ) {
    return this.svc.rotateSigned(deviceId, dto);
  }

  @Post('verify/:deviceId')
  async verifyDevice(
    @Param('deviceId') deviceId: string,
    @Body() dto: VerifyDeviceDto,
  ) {
    if (!deviceId) throw new BadRequestException('Missing deviceId');
    return this.svc.verifyDevice(deviceId, dto);
  }
}
