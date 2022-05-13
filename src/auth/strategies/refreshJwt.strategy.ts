import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from 'src/users/users.service';
import { cookieExtractor } from 'src/helpers/cookieExtractor';
import {Request} from 'express'
import bcrypt from 'bcrypt'
import { AuthService } from '../auth.service';
import { CustomRequest } from 'src/typings';

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(Strategy, 'refreshJwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly authService: AuthService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => cookieExtractor(req, 'refreshToken')
      ]),
      ignoreExpiration: false,
      passReqToCallback: true,
      secretOrKey: configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
    });
  }

  async validate(req: CustomRequest, payload: {email: string, sub: number, sessionId: string}) {
    const {refreshToken} = req.cookies
    const session = await this.authService.fetchSession(payload.sessionId)
    if(!session || (session && session.blacklist)){
      throw new UnauthorizedException()
    }
    const isValid = bcrypt.compareSync(refreshToken, session.hashedRefreshToken)
    if(!isValid){
      throw new UnauthorizedException()
    }
    const user = await this.usersService.findOneByEmail(payload.email);
    if(!user){
      throw new UnauthorizedException()
    }
    req.session = session
    return user;
  }
}
