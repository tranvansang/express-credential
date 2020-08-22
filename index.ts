/* eslint-disable indent */
// eslint-disable-next-line import/no-unresolved
import type {Request, RequestHandler} from 'express'
import asyncMiddleware from 'middleware-async'
import jws, {Algorithm} from 'jws'

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace Express {
		export interface Request {
			user: any
			login: (user: any) => Promise<any>
			logout: () => Promise<void>
		}
	}
}

type Promisable<T> = T | Promise<T>

export interface IStrategy<IPayload, IToken> {
	setPayload: (req: Request, payload: IPayload) => Promisable<IToken>
	getPayload: (req: Request) => Promisable<IPayload | undefined>
	clearPayload: (req: Request) => Promisable<void>
}

export const makeAuthMiddleware = <IUser, IPayload, IToken>(
	encoder: (user: IUser) => Promisable<IPayload>,
	decoder: (payload: IPayload) => Promisable<IUser | undefined>,
	strategy: IStrategy<IPayload, IToken>
): RequestHandler => asyncMiddleware(async (req, res, next) => {
	req.login = async (user?: IUser) => { // set an empty user to logout
		if (user) {
			req.user = user
			return strategy.setPayload(req, await encoder(user))
		}
	}
	req.logout = async () => {
		req.user = undefined
		await strategy.clearPayload(req)
	}
	const payload = await strategy.getPayload(req)
	if (payload) req.user = (await decoder(payload)) || undefined
	else req.user = undefined
	next()
})

export const sessionStrategy = <IPayload>(
	{ key = '__auth' }: { key?: string } = {}
): IStrategy<IPayload, void> => ({
	setPayload(req, payload) {
		if (!payload) req.session![key] = undefined
		else req.session![key] = payload
	},
	getPayload(req) {
		return req.session![key]
	},
	clearPayload(req) {
		req.session![key] = undefined
	}
})
export const jwtStrategy = <IPayload>(
	{
		secret,
		alg = 'HS256',
		ttl,
		isTokenRevoked,
		revokeToken
	}: {
		secret: string
		alg?: Algorithm
		ttl: number
		isTokenRevoked?: (token: string) => Promisable<boolean>
		revokeToken?: (token: string, expire: Date) => Promisable<void>
	}
): IStrategy<IPayload, string> => {
	if (!secret) throw new Error('Secret is required')
	if (!ttl) throw new Error('TTL is required')
	const getPayloadWithTimestamp = async (req: Request) => {
		const authentication = req.get('Authentication')
		if (authentication?.startsWith?.('Bearer ')) {
			const token = authentication.replace(/^Bearer /, '')
			try {
				if (jws.verify(token, alg, secret)) {
					const obj = jws.decode(token)
					if (obj?.header?.alg === alg) {
						const parsed = JSON.parse(obj.payload)
						let {createdAt} = parsed
						const {payload} = parsed
						createdAt = new Date(createdAt)
						if (
							!isNaN(createdAt.getTime())
							&& createdAt.getTime() >= Date.now() - ttl
						) {
							if (await isTokenRevoked?.(token)) return
							return {payload, createdAt}
						}
					}
				}
			} catch {
				//ignored
			}
		}
	}
	return {
		setPayload(req, payload) {
			return jws.sign({
					header: {alg},
					payload: JSON.stringify({
						payload,
						createdAt: Date.now()
					}),
					secret
				},
			)
		},
		async getPayload(req) {
			return (await getPayloadWithTimestamp(req))?.payload
		},
		async clearPayload(req) {
			if (revokeToken) {
				const payloadWithTimestamp = await getPayloadWithTimestamp(req)
				if (payloadWithTimestamp) {
					const {payload, createdAt} = payloadWithTimestamp
					const expire = createdAt.getTime() + ttl
					if (expire > Date.now()) await revokeToken(payload, new Date(expire))
				}
			}
		},
	}
}
