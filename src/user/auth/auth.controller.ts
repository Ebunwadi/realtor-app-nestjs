import { UserType } from '.prisma/client';
import {
  Controller,
  Post,
  Body,
  Get,
  UnauthorizedException,
} from '@nestjs/common';
import { GenerateProductKeyDto, SigninDto, SignupDto } from '../dtos/auth.dto';
import { AuthService } from './auth.service';
import * as bcrypt from 'bcryptjs';
import { User, UserInfo } from '../decorators/user.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signup')
  async signup(@Body() body: SignupDto) {
    if (body.userType !== UserType.BUYER) {
      if (!body.productKey) {
        throw new UnauthorizedException();
      }

      const validProductKey = `${body.email}-${body.userType}-${process.env.PRODUCT_KEY_SECRET}`;

      const isValidProductKey = await bcrypt.compare(
        validProductKey,
        body.productKey,
      );

      if (!isValidProductKey) {
        throw new UnauthorizedException();
      }
    }

    return this.authService.signup(body);
  }

  @Post('/signin')
  signin(@Body() body: SigninDto) {
    return this.authService.signin(body);
  }

  @Post('/key')
  generateProductKey(@Body() { userType, email }: GenerateProductKeyDto) {
    return this.authService.generateProductKey(email, userType);
  }

  @Get('/me')
  me(@User() user: UserInfo) {
    return user;
  }
}
