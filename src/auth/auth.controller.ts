import { Controller, Post, UseGuards, Body, Res, BadRequestException, HttpCode, Get, Req } from '@nestjs/common';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthService } from './auth.service';
import { CurrentUser } from 'src/decorators/currentUser.decorator';
import { User } from 'src/users/user.entity';
import { CreateUserDto } from 'src/dto/create-user.dto';
import { ApiCreatedResponse } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';
import { UsersService } from 'src/users/users.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RefreshJwtAuthGuard } from './guards/refreshJwt-auth.guard';
import { CustomRequest } from 'src/typings';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private configService: ConfigService,
    private usersService: UsersService,
  ) {}
  
  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('login')
  public async login(@CurrentUser() user: User, @Req() req: CustomRequest, @Res({ passthrough: true }) res: Response) {
    const sessionId = this.authService.generateSessionId();
    const token = this.authService.generateJwtToken(user.id, user.email, sessionId);
    const refreshToken = this.authService.generateJwtRefreshToken(user.id, user.email, sessionId);
    const tokenDuration = this.configService.get<number>('JWT_ACCESS_TOKEN_EXPIRATION_TIME');
    const refreshTokenDuration = this.configService.get<number>('JWT_REFRESH_TOKEN_EXPIRATION_TIME');
    const session = this.authService.createSession(sessionId, refreshToken, req)
    await this.authService.saveSession(session)
    res.cookie('accessToken', token, {
      expires: new Date(new Date().getTime() + tokenDuration * 1000),
      httpOnly: true,
    });
    res.cookie('refreshToken', refreshToken, {
      expires: new Date(new Date().getTime() + refreshTokenDuration * 1000),
      httpOnly: true,
    });
    return user; 
  }

  @UseGuards(RefreshJwtAuthGuard)
  @Get('refresh')
  public async refresh(@CurrentUser() user: User, @Req() req: CustomRequest, @Res({ passthrough: true }) res: Response) {
    const session = req.session
    const token = this.authService.generateJwtToken(user.id, user.email, session.id);
    const refreshToken = this.authService.generateJwtRefreshToken(user.id, user.email, session.id);
    const tokenDuration = this.configService.get<number>('JWT_ACCESS_TOKEN_EXPIRATION_TIME');
    const refreshTokenDuration = this.configService.get<number>('JWT_REFRESH_TOKEN_EXPIRATION_TIME');
    await this.authService.updateSession(session, refreshToken, req)
    res.cookie('accessToken', token, {
      expires: new Date(new Date().getTime() + tokenDuration * 1000),
      httpOnly: true,
    });
    res.cookie('refreshToken', refreshToken, {
      expires: new Date(new Date().getTime() + refreshTokenDuration * 1000),
      httpOnly: true,
    });
    return {message: 'Success'};
  }

  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  public async logout(@Req() req: CustomRequest, @Res({ passthrough: true }) res: Response) {
    await this.authService.destroySession(req.session)
    res.clearCookie('accessToken')
    res.clearCookie('refreshToken')
    return {message: 'Logged out successfully'}; 
  }

  @Post('register')
  @ApiCreatedResponse({
    description: 'User created successfully',
    type: User,
  })
  public async register(@Body() userDto: CreateUserDto) {
    const userExists = await this.usersService.findOneByEmail(userDto.email)
    if (userExists) {
      throw new BadRequestException("Email in use")
    }
    userDto.password = await this.authService.hashPassword(userDto.password);
    return this.usersService.create(userDto);
  }

}
