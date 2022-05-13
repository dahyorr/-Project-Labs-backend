import { BadRequestException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/user.entity';
import * as argon2 from "argon2";
import {nanoid} from 'nanoid'
import { ConfigService } from '@nestjs/config';
import { CustomRequest, Session } from 'src/typings';
import dayjs from 'dayjs';
import bcrypt from 'bcrypt'
import { RedisCacheService } from 'src/redis-cache/redis-cache.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redisService: RedisCacheService
  ) {}

  private async verifyPassword(password: string, passwordHash: string) {
    return await argon2.verify(passwordHash, password);
  }

  async hashPassword(password: string){
    return await argon2.hash(password);
  }

  async validateUser(email: string, password: string): Promise<Partial<User>> {
    const user = await this.usersService.findOneByEmail(email);
    if (user) {
      const { password: passwordHash, ...result } = user;
      if (await this.verifyPassword(password, passwordHash)) {
        return result;
      }
      throw new BadRequestException("Invalid email/password");
    }
    throw new BadRequestException("Invalid email/password");
  }

  generateJwtToken(id: number, email: string, sessionId: string) {
    const payload = {email, sub: id, sessionId}
    const token = this.jwtService.sign(payload);
    return token;
  }
  
  generateJwtRefreshToken(id: number, email: string, sessionId: string) {
    const payload = {email, sub: id, sessionId}
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME')}s`
    });
    return token;
  }

  generateSessionId(): string{
    return nanoid()
  }

  createSession(sessionId: string, refreshToken: string, req: CustomRequest ){
    const session: Session = {
      id: sessionId,
      userId: req.user.id,
      lastIpUsed: req.clientIp,
      created: dayjs().toISOString(),
      lastUsed: dayjs().toISOString(),
      hashedRefreshToken: bcrypt.hashSync(refreshToken, 10),
      blacklist: false
    }
    return session
  }

  async fetchSession(sessionId: string){
    return await this.redisService.get<Session>(sessionId)
  }

  async updateSession(session: Session, refreshToken: string, req: CustomRequest){
    session.lastIpUsed = req.clientIp,
    session.lastUsed = dayjs().toISOString(),
    session.hashedRefreshToken = bcrypt.hashSync(refreshToken, 10)
    await this.saveSession(session)
  }

  async saveSession(session: Session){
    console.log(session)
    return await this.redisService.set(
      session.id, 
      session,
      {
        ttl: this.configService.get<number>('JWT_REFRESH_TOKEN_EXPIRATION_TIME')
      }
    )
  }

  async destroySession(session: Session){
    this.redisService.del(session.id)
    // delete from db
    return;
  }
  
}