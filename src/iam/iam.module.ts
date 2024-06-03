import {MiddlewareConsumer, Module, NestModule} from '@nestjs/common';
import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';
import { AuthenticationController } from './authentication/authentication.controller';
import { AuthenticationService } from './authentication/authentication.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import jwtConfig from './config/jwt.config';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AccessTokenGuard } from './authentication/guards/access-token/access-token.guard';
import { AuthenticationGuard } from './authentication/guards/authentication/authentication.guard';
import {RefreshTokenIdsStorage} from "./authentication/refresh-token-ids.storage/refresh-token-ids.storage";
// import {RolesGuard} from "./authorization/guards/roles/roles.guard";
// import {PermissionsGuard} from "./authorization/guards/permissions.guard";
import {PolicyHandlerStorage} from "./authorization/policies/policy-handlers.storage";
import {FrameworkContributorPolicyHandler} from "./authorization/policies/framework-contributor.policy";
import {PoliciesGuard} from "./authorization/guards/policies.guard";
import { ApiKeysService } from './authentication/api-keys.service';
import {ApiKey} from "../users/api-keys/entities/api-key.entity/api-key.entity";
import {ApiKeyGuard} from "./authentication/guards/api-key/api-key.guard";
import { GoogleAuthenticationService } from './authentication/social/google-authentication.service';
import { GoogleAuthenticationController } from './authentication/social/google-authentication.controller';
import { OtpAuthenticationService } from './authentication/otp-authentication.service';
import { SessionAuthenticationService } from './authentication/session-authentication.service';
import { SessionAuthenticationController } from './authentication/session-authentication.controller';
import * as session from 'express-session';
import * as passport from 'passport';
import { UserSerializer } from './authentication/serializers/user-serializer/user-serializer';
import * as createRedisStore from 'connect-redis';
import connectRedis, {RedisStore} from 'connect-redis';
import Redis from 'ioredis';

@Module({
    imports: [
        TypeOrmModule.forFeature([User, ApiKey]),
        JwtModule.registerAsync(jwtConfig.asProvider()),
        ConfigModule.forFeature(jwtConfig),
    ],
    providers: [
        {
            provide: HashingService,
            useClass: BcryptService,
        },
        {
            provide: APP_GUARD,
            useClass: AuthenticationGuard,
        },
        {
            provide: APP_GUARD,
            useClass: PoliciesGuard, // RolesGuard,
        },
        AccessTokenGuard,
        ApiKeyGuard,
        RefreshTokenIdsStorage,
        AuthenticationService,
        PolicyHandlerStorage,
        FrameworkContributorPolicyHandler,
        ApiKeysService,
        OtpAuthenticationService,
        GoogleAuthenticationService,
        SessionAuthenticationService,
        UserSerializer,
    ],
    controllers: [
        AuthenticationController,
        GoogleAuthenticationController,
        SessionAuthenticationController,
    ],
})
export class IamModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
        const RedisStore = require("connect-redis").default;

        consumer
            .apply(
                session({
                    store: new RedisStore({ client: new Redis(6379, 'nest-auth-redis') }),
                    secret: process.env.SESSION_SECRET,
                    resave: false,
                    saveUninitialized: false,
                    cookie: {
                        sameSite: true,
                        httpOnly: true,
                    },
                }),
                passport.initialize(),
                passport.session(),
            )
            .forRoutes('*');
    }
}
