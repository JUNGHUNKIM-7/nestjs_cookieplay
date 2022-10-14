import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtPayload } from '../types';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { Request } from 'express';
import { assert } from 'console';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'rt-jwt') {
    constructor(private readonly p: PrismaService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'rt-secret',
            passReqToCallback: true,
        });
    }

    async validate(
        req: Request, //from passReqToCallback
        payload: JwtPayload,
    ): Promise<JwtPayload> {
        const { rToken } = await this.p.user.findUnique({
            where: { email: payload.email },
        });
        const { rt } = req.cookies.token;
        assert(rToken !== null, 'rt(from db)is null now');
        assert(rt !== null, 'rt is null now');

        const rtMatches = await argon.verify(rToken, rt);

        if (!rtMatches) {
            throw new ForbiddenException('rt not matches');
        } else {
            return {
                ...payload,
                rt: rt,
            };
        }
    }
}
