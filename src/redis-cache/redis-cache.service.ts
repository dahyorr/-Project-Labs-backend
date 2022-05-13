import { CACHE_MANAGER, Inject, Injectable } from '@nestjs/common';
import { Cache, CachingConfig } from 'cache-manager';

@Injectable()
export class RedisCacheService{
  constructor(@Inject(CACHE_MANAGER) public readonly cacheManager: Cache) {
  }


  async set<T>(key: string, value: T, options?: CachingConfig) {
    /* set value in cache */
    return await this.cacheManager.set<T>(key, value, options);
  }

  async get<T>(key: string){
    /* retrieve value from cache */
    return await this.cacheManager.get<T>(key);
  }

  async del(key: string){
    /* delete value from cache */
    return await this.cacheManager.del(key);
  }
}
