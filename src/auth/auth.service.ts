import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as argon from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Auth, JwtPayload, Token } from './types';

@Injectable()
export class AuthService implements Auth {
    constructor(
        private readonly p: PrismaService,
        private readonly jwt: JwtService,
    ) {}

    async signUp(
        { email, password: plainPassword }: CreateAuthDto,
    ): Promise<Token> {
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

        // //save at to cookie
        // req.cookies['token'] = { at, rt };

        // //send cookie
        // res.cookie('token', { at, rt });
        return {
            at,
            rt,
        };
    }

    async signIn(
        { email, password }: CreateAuthDto,
    ): Promise<Token> {
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
        // req.cookies['token'] = { at, rt };

        //send cookie
        // res.cookie('token', { at, rt });

        return {
            at,
            rt,
        };
    }

    async signOut({ email }: JwtPayload): Promise<void> {
        //clean rToken
        await this.p.user.updateMany({
            where: { email, rToken: { not: null } },
            data: { rToken: null },
        });
    }

    async changePwd(
        { email }: JwtPayload,
        { password }: UpdateAuthDto,
    ): Promise<void> {
        //get user email from cookie
        const u = await this.p.user.findUnique({ where: { email } });
        if (!u) throw new ForbiddenException('not found user');

        //then update
        await this.p.user.update({
            where: { email },
            data: { password: await argon.hash(password) },
        });
    }

    async refresh(user: JwtPayload): Promise<void> {
        //find user from cookie
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
                expiresIn: '1m',
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
        await this.p.user.update({
            where: { email },
            data: { rToken: await argon.hash(rt) },
        });
    }
}
