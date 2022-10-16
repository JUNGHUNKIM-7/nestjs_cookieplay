import { Request, Response } from 'express';
import { CreateAuthDto } from '../dto/create-auth.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';

export interface Token {
    at: string;
    rt: string;
    updatedAt: string;
}

export interface Auth {
    signUp(dto: CreateAuthDto, req: Request, res: Response): Promise<Token>;
    signIn(dto: CreateAuthDto, req: Request, res: Response): Promise<Token>;
    signOut(payload: JwtPayload): Promise<void>;
    changePwd(payload: JwtPayload, body: UpdateAuthDto): Promise<void>;
    refresh(payload: JwtPayload): Promise<Token>;
}

export interface JwtPayload {
    sub: string;
    email: string;
    rt?: string;
}
