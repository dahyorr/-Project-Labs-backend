import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from 'src/users/users.service';
import { cookieExtractor } from 'src/helpers/cookieExtractor';
import {Request} from 'express'
import { AuthService } from '../auth.service';
import { CustomRequest } from 'src/typings';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly authService: AuthService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => cookieExtractor(req, 'accessToken')
      ]),
      ignoreExpiration: false,
      passReqToCallback: true,
      secretOrKey: configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
    });
  }

  async validate(req: CustomRequest, payload: {email: string, sub: number, sessionId: string}) {
    const session = {id: payload.sessionId}
    req.session = session
    const user = await this.usersService.findOneByEmail(payload.email);
    return user;
  }
}
