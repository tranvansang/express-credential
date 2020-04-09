import { Request, RequestHandler } from 'express';
declare global {
    namespace Express {
        interface Request {
            user: any;
            login: (user?: any) => Promise<any>;
            logout: () => Promise<void>;
        }
    }
}
export interface IStrategy<IPayload, IToken> {
    setPayload: (req: Request, payload?: IPayload) => Promise<IToken | void> | IToken | void;
    getPayload: (req: Request) => Promise<IPayload | void>;
}
export declare const makeAuthMiddleware: <IUser, IPayload, IToken>(encoder: (user: IUser) => Promise<IPayload>, decoder: (payload: IPayload) => Promise<IUser | undefined>, strategy: IStrategy<IPayload, IToken>) => RequestHandler<import("express-serve-static-core").ParamsDictionary>;
export declare const sessionStrategy: <IPayload>({ expire, key }?: {
    expire?: number | undefined;
    key?: string | undefined;
}) => IStrategy<IPayload, undefined>;
export declare const jwtStrategy: <IPayload>({ secret, alg, expire }: {
    secret: string;
    alg?: "none" | "HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512" | undefined;
    expire?: number | undefined;
}) => IStrategy<IPayload, string>;
