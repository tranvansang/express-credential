import type {Request, RequestHandler} from 'express'
// eslint-disable-next-line import/no-unresolved
import type {CookieOptions} from 'express-serve-static-core'
import asyncMiddleware from 'middleware-async'
import jws, {Algorithm, ALGORITHMS} from 'jws'
import ms from 'ms'

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

type CanAwait<T> = T | Promise<T>

const allAlgorithms = [...ALGORITHMS, 'none']
const bearerPrefix = 'Bearer '

export async function extractAndVerify(
	req: Request,
	{cookieKey, secret, isTokenRevoked, alg, encoding}: {
		secret: string | Buffer
		alg: Algorithm
		isTokenRevoked?: (token: string) => CanAwait<boolean>
		cookieKey: string | false
		encoding: string
	}
) {
	let token
	const authentication = req.header('Authentication')
	if (authentication?.startsWith?.(bearerPrefix)) token = authentication.slice(bearerPrefix.length)
	else if (cookieKey) token = req.cookies[cookieKey]
	if (token) {
		try {
			if (jws.verify(token, alg, secret)) {
				// TODO: @types/jws is not up-to-date
				// eslint-disable-next-line @typescript-eslint/ban-ts-comment
				// @ts-ignore
				const {payload, header: {expires}} = jws.decode(token, {encoding})
				if (expires) {
					const expiresDate = new Date(expires)
					if (
						!isNaN(expiresDate.getTime())
						&& expiresDate.getTime() >= Date.now()
					) {
						if (await isTokenRevoked?.(token)) return
						return {payload: JSON.parse(payload), expires: expiresDate, token}
					}
				}
			}
		} catch {
			//ignored
		}
	}
}

export default function connectAuthentication<IUser, IPayload>(
	encode: (user: IUser) => CanAwait<IPayload>,
	decode: (payload: IPayload) => CanAwait<IUser | undefined>,
	secret: string | Buffer,
	{
		ttl = '1 week',
		alg = 'HS256',
		encoding = 'utf8',
		cookieKey = 'jwt',
		isTokenRevoked,
		revokeToken,
		cookieOptions = {
			httpOnly: true,
			sameSite: 'lax',
			secure: true,
			signed: false,
		},
	}: {
		ttl?: number | string
		alg?: Algorithm
		encoding?: string
		cookieKey?: string | false
		isTokenRevoked?: (token: string) => CanAwait<boolean>
		revokeToken?: (token: string, expire: Date) => CanAwait<void>
		cookieOptions?: CookieOptions
	} = {}
): RequestHandler {
	if (!secret) throw new Error('Secret is required')
	if (!allAlgorithms.includes(alg)) throw new Error(`alg must be one of ${allAlgorithms.join(', ')}`)
	const subOptions = {cookieKey, secret, ttl, isTokenRevoked, alg, encoding}
	const timeToLive = typeof ttl === 'string' ? ms(ttl) : ttl
	return asyncMiddleware(async (req, res, next) => {
		req.login = async (user: IUser) => {
			req.user = user
			const expires = Date.now() + timeToLive
			const token = jws.sign({
				header: {alg, expires},
				payload: JSON.stringify(await encode(user)),
				secret,
				encoding,
			})
			if (cookieKey) res.cookie(cookieKey, token, {
				...cookieOptions,
				expires: new Date(expires),
			})
			return token
		}
		req.logout = async () => {
			req.user = undefined
			if (cookieKey) res.clearCookie(cookieKey, {
				...cookieOptions,
				expires: undefined,
				maxAge: undefined
			})
			if (revokeToken) {
				const info = await extractAndVerify(req, subOptions)
				if (info) {
					const {expires, token} = info
					await revokeToken(token, expires)
				}
			}
		}
		req.user = undefined
		const payload = (await extractAndVerify(req, subOptions))?.payload
		if (payload) req.user = (await decode(payload)) || undefined
		next()
	})
}
