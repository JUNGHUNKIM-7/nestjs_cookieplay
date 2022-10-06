import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { Auth, JwtPayload, Token } from './types';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as argon from 'argon2';
import { Request, Response } from 'express';

@Injectable()
export class AuthService implements Auth {
    constructor(
        private readonly p: PrismaService,
        private readonly jwt: JwtService,
    ) {}

    async signUp(
        { email, password: plainPassword }: CreateAuthDto,
        req: Request,
        res: Response,
    ): Promise<void> {
        let user: User;

        //find user
        user = await this.p.user.findUnique({ where: { email } });
        if (user) throw new ForbiddenException('user is already taken');

        //hashed password
        const password = await argon.hash(plainPassword);

        //create user
        user = await this.p.user.create({
            data: {
                email,
                password,
                rToken: null,
            },
        });

        //create token
        const { at, rt } = await this.makeToken(user.id, user.email);

        //update rt token
        await this.updateRtToken(email, rt);

        //save at to cookie
        req.cookies['token'] = { at, rt };

        //send cookie
        res.cookie('token', { at, rt });
    }

    async signIn(
        { email, password }: CreateAuthDto,
        req: Request,
        res: Response,
    ): Promise<void> {
        //find user
        const user = await this.p.user.findUnique({ where: { email } });
        if (!user) throw new ForbiddenException('not found user');

        //password verify
        const pwMatches = await argon.verify(user.password, password);
        if (!pwMatches) throw new ForbiddenException('password not matches');

        //create token
        const { at, rt } = await this.makeToken(user.id, user.email);

        //update rt token
        await this.updateRtToken(email, rt);

        //save at to cookie
        req.cookies['token'] = { at, rt };

        //send cookie
        res.cookie('token', { at, rt });
    }

    async signOut({ email }: JwtPayload): Promise<void> {
        //clean rToken
        await this.p.user.updateMany({
            where: { email, rToken: { not: null } },
            data: { rToken: null },
        });
    }

    async chagnePassword(payload: JwtPayload): Promise<void> {
        throw new Error('Method not implemented.');
    }

    async refresh(user: JwtPayload): Promise<void> {
        const u = await this.p.user.findUnique({
            where: { email: user.email },
        });
        if (!u) throw new ForbiddenException('not found user');

        //match hashed rtoken and rtToken
        const rtMatches = await argon.verify(u.rToken, user.rt);
        if (!rtMatches) throw new ForbiddenException('rt token not matches');

        //matches, make new token
        const { rt: newRt } = await this.makeToken(u.id, user.email);

        //then update
        await this.updateRtToken(user.email, newRt);
    }

    async makeToken(sub: string, email: string): Promise<Token> {
        const [at, rt] = await Promise.all([
            this.jwt.signAsync({ sub, email }, {
                secret: 'at-secret',
                expiresIn: '5m',
            }),
            this.jwt.signAsync({ sub, email }, {
                secret: 'rt-secret',
                expiresIn: '1d',
            }),
        ]);
        return {
            at,
            rt,
        };
    }

    async updateRtToken(email: string, rt: string): Promise<void> {
        const rToken = await argon.hash(rt);
        await this.p.user.update({
            where: { email },
            data: { rToken },
        });
    }
}
