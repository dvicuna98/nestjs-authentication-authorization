import {Injectable, OnApplicationBootstrap, OnApplicationShutdown} from "@nestjs/common";
import Redis from "ioredis";

export class InvalidatedRefreshTokenError extends Error {}

@Injectable()
export class RefreshTokenIdsStorage
    implements OnApplicationBootstrap, OnApplicationShutdown
{
    private redisClient: Redis;

    onApplicationBootstrap(): any {
        // TODO: Ideally, we should move this to the dedicated "RedisModule"
        // instead of initiating the connection here.
        this.redisClient = new Redis({
            host: 'nest-auth-redis', // NOTE: According to best practices, we should use the environment variables here instead.
            port: 6379, // 👆
        });
    }

    onApplicationShutdown(signal?: string): any {
        return this.redisClient.quit();
    }

    async insert(userId: number, tokenId: string): Promise<void> {
        await this.redisClient.set(this.getKey(userId), tokenId);
    }

    async validate(userId: number, tokenId: string): Promise<boolean> {
        const storedId = await this.redisClient.get(this.getKey(userId));
        if (storedId !== tokenId) {
            throw new InvalidatedRefreshTokenError();
        }
        return storedId === tokenId;
    }

    async invalidate(userId: number): Promise<void> {
        await this.redisClient.del(this.getKey(userId));
    }

    private getKey(userId: number): string {
        return `user-${userId}`;
    }
}
