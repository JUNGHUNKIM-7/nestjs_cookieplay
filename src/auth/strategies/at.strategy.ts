import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { JwtPayload } from '../types';
import { PrismaService } from 'src/prisma/prisma.service';
import { assert } from 'console';
import { ForbiddenException, Injectable } from '@nestjs/common';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'at-jwt') {
    constructor(
        private readonly p: PrismaService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'at-secret',
        });
    }

    async validate(payload: JwtPayload): Promise<JwtPayload> {
        const { email } = payload;
        console.log(email);
        assert(email !== null, 'email is null now');
        const user = await this.p.user.findUnique({ where: { email } });
        if (!user) throw new ForbiddenException('user not found');

        return payload;
    }
}
// validate(payload =  {
// "sub" :  ..,
// "email": ..
// "iat"
// "eat"
// }) {}
