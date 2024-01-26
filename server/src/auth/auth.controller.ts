import {Controller, Post, Body, Req, Res, Get} from '@nestjs/common';
import { AuthService } from './auth.service';
import {RegisterAuthDto} from "./dto/register-auth.dto";
import {LoginAuthDto} from "./dto/login-auth.dto";
import {Request} from "express";
import {Response} from "express";

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterAuthDto, @Res({passthrough: true}) response: Response) {
    const tokens = await this.authService.register(dto);
    response.cookie('refreshToken', tokens.refreshToken)
    return tokens
  }

  @Post('login')
  async login(@Body() dto: LoginAuthDto, @Res({ passthrough: true }) response: Response) {
    const tokens = await this.authService.login(dto);
    response.cookie('refreshToken', tokens.refreshToken)
    return tokens
  }

  @Get('refresh')
  async refresh(@Req() request: Request, @Res({ passthrough: true }) response: Response) {
    const tokens = await this.authService.refresh(request.cookies.refreshToken);
    response.cookie('refreshToken', tokens.refreshToken)
    return tokens
  }

  @Get('logout')
  logout(@Req() request: Request, @Res({ passthrough: true }) response: Response) {
    response.clearCookie('refreshToken')
    return this.authService.logout(request.cookies.refreshToken);
  }
}
