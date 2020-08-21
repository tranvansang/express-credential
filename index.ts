/* eslint-disable indent */
// eslint-disable-next-line import/no-unresolved
import {Request, RequestHandler} from 'express'
import ms from 'ms'
import asyncMiddleware from 'middleware-async'
import jws, {Algorithm} from 'jws'

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace Express {
		export interface Request {
			user: any
			login: (user?: any) => Promise<any>
			logout: () => Promise<void>
		}
	}
}

export interface IStrategy<IPayload, IToken> {
	setPayload: (req: Request, payload?: IPayload) => Promise<IToken | void> | IToken | void
	getPayload: (req: Request) => Promise<IPayload | void>
}

export const makeAuthMiddleware = <IUser, IPayload, IToken>(
	encoder: (user: IUser) => Promise<IPayload>,
	decoder: (payload: IPayload) => Promise<IUser | undefined>,
	strategy: IStrategy<IPayload, IToken>
): RequestHandler => asyncMiddleware(async (req, res, next) => {
	req.login = async (user?: IUser) => {
		if (user) {
			req.user = user
			return strategy.setPayload(req, await encoder(user))
		}
		req.user = undefined
		await strategy.setPayload(req, undefined)
	}
	req.logout = async () => {
		await req.login()
	}
	const payload = await strategy.getPayload(req)
	if (payload) req.user = (await decoder(payload)) || undefined
	else req.user = undefined
	next()
})

export const sessionStrategy = <IPayload>(
	{
		expire = ms('14 days'),
		key = '__auth'
	}: {
		expire?: number
		key?: string
	} = {}
): IStrategy<IPayload, undefined> => ({
	setPayload: (req, payload) => {
		if (!payload) req.session![key] = undefined
		else req.session![key] = {
			payload,
			createdAt: new Date().toISOString()
		}
	},
	getPayload: req => {
		if (req.session![key]) {
			let {createdAt} = req.session![key]
			const {payload} = req.session![key]
			if (payload && createdAt) {
				createdAt = new Date(createdAt)
				if (!isNaN(createdAt.getTime()) && createdAt.getTime() >= Date.now() - expire) return payload
			}
			req.session![key] = undefined
		}
	}
})
export const jwtStrategy = <IPayload>(
	{
		secret,
		alg = 'HS256',
		expire = ms('14 days')
	}: {
		secret: string
		alg?: Algorithm
		expire?: number
	}
): IStrategy<IPayload, string> => ({
	setPayload: (req, payload) => {
		if (payload) return jws.sign({
				header: {alg},
				payload: JSON.stringify({
					payload,
					createdAt: new Date().toISOString()
				}),
				secret
			},
		)
	},
	getPayload: req => {
		if (req.get('Authentication')?.startsWith?.('Bearer ')) {
			const token = req.get('Authentication')!.replace(/^Bearer /, '')
			try {
				if (jws.verify(token, alg, secret)) {
					const obj = jws.decode(token)
					if (obj && obj.header?.alg === alg) {
						//after a positive verification, this conditional branch is always positive
						let {createdAt} = JSON.parse(obj.payload)
						const {payload} = JSON.parse(obj.payload)
						if (payload && createdAt) {
							createdAt = new Date(createdAt)
							if (
								!isNaN(createdAt.getTime())
								&& createdAt.getTime() >= Date.now() - expire
							) return payload
						}
					}
				}
			} catch {
				//ignored
			}
		}
	}
})
