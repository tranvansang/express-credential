/* eslint-disable import/no-extraneous-dependencies */
import flipPromise from 'flip-promise'
import jws from 'jws'
import {jwtStrategy, makeAuthMiddleware, sessionStrategy} from './index'
import {combineToAsync} from 'middleware-async'
import ms from 'ms'

const payload = {foo: {bar: 'baar'}, fooo: 1}
const makeJwtReq = (authHeader: string) => ({
	get: () => authHeader
})

const ttl = ms('7 days')
describe('JWT strategy', () => {
	const secret = 'my secret'
	const {setPayload, getPayload} = jwtStrategy({secret, ttl})
	test('basic tests', async () => {
		const token = await setPayload(payload, payload)
		expect(typeof token).toBe('string')
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toEqual(payload)
		expect(await getPayload(makeJwtReq(token))).toBeUndefined()
		expect(await getPayload(makeJwtReq('Bearer 123'))).toBeUndefined()
		expect(await getPayload(makeJwtReq('Bearer 123.456'))).toBeUndefined()
		expect(await getPayload(makeJwtReq('Bearer 123.456.789'))).toBeUndefined()
	})
	test('incorrect secret', async () => {
		const token = jwtStrategy({secret: '123', ttl}).setPayload(undefined, payload)
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
	test('incorrect algorithm', async () => {
		const token = jwtStrategy({secret, alg: 'HS384', ttl}).setPayload(undefined, payload)
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
	test('different expire', async () => {
		const token = jwtStrategy({secret, ttl}).setPayload(undefined, payload)
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toEqual(payload)
	})
	test('expired', async () => {
		const token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({payload, createdAt: new Date(Date.now() - ms('15 days')).toISOString()}),
			secret
		})
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
	test('malformed payload', async () => {
		let token = jws.sign({
			header: {alg: 'HS256'},
			payload: 'an invalid json',
			secret
		})
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
		token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({createdAt: new Date()}),
			secret
		})
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
		token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({payload}),
			secret
		})
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
		token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({payload, createdAt: 'an invalid date'}),
			secret
		})
		expect(await getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})

	test('revokeToken', async () => {
		const revokeToken = jest.fn()
		const isTokenRevoked = jest.fn()
		const strategy = jwtStrategy({secret, ttl, revokeToken, isTokenRevoked})
		const token = await strategy.setPayload(undefined, payload)
		const now = Date.now()
		const req = makeJwtReq(`Bearer ${token}`)
		expect(await getPayload(req)).toEqual(payload)
		await strategy.clearPayload(req)
		expect(revokeToken.mock.calls.length).toBe(1)
		expect(revokeToken.mock.calls[0][0]).toEqual(payload)
		expect(revokeToken.mock.calls[0][1].getTime()).toBeLessThanOrEqual(now + ttl)

		revokeToken.mockClear()
		await strategy.clearPayload(makeJwtReq('invalid header'))
		expect(revokeToken.mock.calls.length).toBe(0)
	})
	test('isTokenRevoked', async () => {
		let revoked
		const revokeToken = jest.fn()
		const isTokenRevoked = tk => tk === revoked
		const strategy = jwtStrategy({secret, ttl, revokeToken, isTokenRevoked})
		const token = await strategy.setPayload(undefined, payload)
		const req = makeJwtReq(`Bearer ${token}`)
		expect(await getPayload(req)).toEqual(payload)
		revoked = token
		expect(await strategy.getPayload(req)).toBeUndefined()
	})
})

describe('Session Strategy', () => {
	const {getPayload, setPayload} = sessionStrategy()
	test('basic', async () => {
		expect(setPayload({session: {}})).toBeUndefined()
	})
	describe('set', () => {
		test('remove payload', async () => {
			const req = {session: {__auth: 123}}
			await setPayload(req)
			expect(req.session.__auth).toBeUndefined()
		})
	})
	test('set and get', async () => {
		const req = {session: {}}
		setPayload(req, payload)
		expect(await getPayload(req)).toEqual(payload)
	})
	describe('get', () => {
		test('empty session', async () => {
			expect(await getPayload({session: {}})).toBeUndefined()
		})
		test('malformed session', async () => {
			let req = {session: {__auth: 1}}
			expect(await getPayload(req)).toBe(1)
			req = {session: {__auth: payload}}
			expect(await getPayload(req)).toBe(payload)
		})
	})
})

describe('Authentication middleware', () => {
	const user = {id: 'user id', username: 'my username'}
	const encoder = ({id}) => Promise.resolve(id)
	const decoder = id => Promise.resolve(id === user.id ? user : undefined)
	test('with jwt strategy', async () => {
		await flipPromise((async () => jwtStrategy())())
		await flipPromise((async () => jwtStrategy({}))())
		await flipPromise((async () => jwtStrategy({secret: 'a'}))())
		await flipPromise((async () => jwtStrategy({ttl: 10}))())
		await jwtStrategy({ttl: 10, secret: 'a'})
		const auth = makeAuthMiddleware(
			encoder,
			decoder,
			jwtStrategy({secret: 'my secret', ttl})
		)
		let req = makeJwtReq('123')
		await combineToAsync(auth)(req)
		expect(req.user).toBeUndefined()
		const token = await req.login(user)
		expect(req.user).toEqual(user)
		await req.logout()
		expect(req.user).toBeUndefined()

		req = makeJwtReq(`Bearer ${token}`)
		await combineToAsync(auth)(req)
		expect(req.user).toEqual(user)
		await req.login(null)
		expect(req.user).toEqual(user)
	})
	test('with session strategy', async () => {
		const auth = makeAuthMiddleware(
			encoder,
			decoder,
			sessionStrategy()
		)
		const req = {session: {}}
		await combineToAsync(auth)(req)
		expect(req.user).toBeUndefined()
		await req.login(user)
		const session = req.session.__auth
		expect(req.user).toEqual(user)
		await req.logout()
		expect(req.user).toBeUndefined()

		req.session.__auth = session
		await combineToAsync(auth)(req)
		expect(req.user).toEqual(user)
		await req.login(null)
		expect(req.user).toEqual(user)
	})
	test('load different info', async () => {
		const auth = makeAuthMiddleware(
			encoder,
			decoder,
			sessionStrategy()
		)
		const req = {session: {}}
		await combineToAsync(auth)(req)
		await req.login({id: 'another id'})
		await combineToAsync(auth)(req)
		expect(req.user).toBeUndefined()
	})
})
