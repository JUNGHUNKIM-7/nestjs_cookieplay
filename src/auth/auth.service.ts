import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { User } from "@prisma/client";
import * as argon from "argon2";
import { PrismaService } from "src/prisma/prisma.service";
import { CreateAuthDto } from "./dto/create-auth.dto";
import { UpdateAuthDto } from "./dto/update-auth.dto";
import { Auth, JwtPayload, Token } from "./types";

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
    if (user) throw new HttpException("user exist", HttpStatus.BAD_REQUEST);

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
    const { at, rt, updatedAt } = await this.makeToken(user.id, user.email);

    //update rt token
    await this.updateRtToken(email, rt);

    return {
      at,
      rt,
      updatedAt,
    };
  }

  async signIn(
    { email, password }: CreateAuthDto,
  ): Promise<Token> {
    //find user
    const user = await this.p.user.findUnique({ where: { email } });
    if (!user) {
      throw new HttpException(
        "not found user",
        HttpStatus.NOT_FOUND,
      );
    }

    //password verify
    const pwMatches = await argon.verify(user.password, password);
    if (!pwMatches) {
      throw new HttpException("pw not matches", HttpStatus.BAD_REQUEST);
    }

    //create token
    const { at, rt, updatedAt } = await this.makeToken(user.id, user.email);

    //update rt token
    await this.updateRtToken(email, rt);

    return {
      at,
      rt,
      updatedAt,
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
    if (!u) throw new HttpException("not found user", HttpStatus.NOT_FOUND);

    //then update
    await this.p.user.update({
      where: { email },
      data: { password: await argon.hash(password) },
    });
  }

  async refresh(user: JwtPayload): Promise<Token> {
    //find user from cookie
    const u = await this.p.user.findUnique({
      where: { email: user.email },
    });

    if (!u) throw new HttpException("not found user", HttpStatus.NOT_FOUND);

    //match hashed rtoken and rtToken
    const rtMatches = await argon.verify(u.rToken, user.rt);
    if (!rtMatches) {
      throw new HttpException("rt token invalid", HttpStatus.BAD_REQUEST);
    }

    //matches, make new token
    const { at, rt: newRt, updatedAt } = await this.makeToken(
      u.id,
      user.email,
    );

    //then update
    await this.updateRtToken(user.email, newRt);

    return {
      at,
      rt: newRt,
      updatedAt,
    };
  }

  async makeToken(sub: string, email: string): Promise<Token> {
    const [at, rt] = await Promise.all([
      this.jwt.signAsync({ sub, email }, {
        secret: "at-secret",
        expiresIn: "15m",
      }),
      this.jwt.signAsync({ sub, email }, {
        secret: "rt-secret",
        expiresIn: "1d",
      }),
    ]);

    const user = await this.p.user.findUnique({ where: { email } });
    if (!user) {
      throw new HttpException("user not exist", HttpStatus.NOT_FOUND);
    }

    return {
      at,
      rt,
      updatedAt: user.updatedAt.toISOString(),
    };
  }

  async updateRtToken(email: string, rt: string): Promise<void> {
    await this.p.user.update({
      where: { email },
      data: { rToken: await argon.hash(rt) },
    });
  }

  async deleteAllForDebug(): Promise<void> {
    await this.p.user.deleteMany({});
  }
}
