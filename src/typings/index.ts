import { Request } from "express";

export interface User {
  id: number;
  name: string;
  email: string;
  password: string;
}

export interface Session{
  id: string;
  created?: string;
  lastUsed?: string;
  hashedRefreshToken?: string;
  userId?: number;
  lastIpUsed?: string;
  blacklist?: boolean;
}

export interface CustomRequest extends Request{
  user: Omit<User, 'password'>;
  session?: Session;
}

export interface UserSession {
  sub: number;
  email: string;
  session: Session;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}