import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtPayload } from '../types';
import { PrismaService } from 'src/prisma/prisma.service';
import { Request } from 'express';
import { assert } from 'console';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'at-jwt') {
    constructor(
        private readonly p: PrismaService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (req: Request) => {
                    const { cookies: { token: at } } = req;
                    assert(at !== null, 'at token is null');
                    if (req.cookies && at !== null) {
                        return at;
                    } else return null;
                },
            ]),
            secretOrKey: 'at-secret',
        });
    }

    // validate(payload =  {
    // "sub" :  ..,
    // "email": ..
    // "iat"
    // "eat"
    // }) {}

    async validate(payload: JwtPayload): Promise<JwtPayload> {
        const { email } = payload;
        assert(email !== null, 'email is null now');

        const user = await this.p.user.findUnique({ where: { email } });
        if (!user) throw new ForbiddenException('user not found');
        return payload;
    }
}
