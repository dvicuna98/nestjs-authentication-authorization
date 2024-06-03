import {Body, Controller, HttpCode, HttpStatus, Post, Res} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { Auth } from './decorators/auth.decorator';
import { AuthType } from './enums/auth-type.enum';
import {RefreshTokenDto} from "./dto/refresh-token.dto";
import {ActiveUser} from "../decorators/active-user.decorator";
import {ActiveUserData} from "../interfaces/active-user-data.interface";
import {OtpAuthenticationService} from "./otp-authentication.service";
import {toFileStream} from "qrcode";
import {Response} from 'express';

@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
  constructor(
      private readonly authService: AuthenticationService,
      private readonly otpAuthService:OtpAuthenticationService
  ) {}

  @Post('sign-up')
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @HttpCode(HttpStatus.OK) // by default @Post does 201, we wanted 200 - hence using @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }

  @HttpCode(HttpStatus.OK) // changed since the default is 201
  @Post('refresh-tokens')
  refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto);
  }

  // @HttpCode(HttpStatus.OK) // by default @Post does 201, we wanted 200 - hence using @HttpCode(HttpStatus.OK)
  // @Post('sign-in')
  // async signIn(
  //   @Res({passthrough:true}) response:Response,
  //   @Body() signInDto: SignInDto
  // ) {
  //   const accessToken = await this.authService.signIn(signInDto);
  //   response.cookie('accessToken', accessToken, {
  //     secure: true,
  //     httpOnly: true,
  //     sameSite: true,
  //   });
  // }

  @Auth(AuthType.Bearer)
  @HttpCode(HttpStatus.OK)
  @Post('2fa/generate')
  async generateQrCode(
      @ActiveUser() activeUser: ActiveUserData,
      @Res() response: Response,
  ) {
    const { secret, uri } = await this.otpAuthService.generateSecret(
        activeUser.email,
    );
    await this.otpAuthService.enableTfaForUser(activeUser.email, secret);
    response.type('png');
    return toFileStream(response, uri);
  }
}