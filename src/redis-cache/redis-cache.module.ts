import { CacheModule, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RedisCacheService } from './redis-cache.service';
import redisStore from 'cache-manager-redis-store';
import { RedisClientOptions } from 'redis';

@Module({
  providers: [RedisCacheService],
  imports: [
    CacheModule.registerAsync<RedisClientOptions>({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        store: redisStore,
        // url: configService.get<string>('REDIS_URL'),
        socket: {
          host: configService.get<string>('REDIS_HOST'),
          port: configService.get<number>('REDIS_PORT'),
        },
        ttl: 120
      })
    })
  ],
  exports: [RedisCacheService],
})
export class RedisCacheModule {}
