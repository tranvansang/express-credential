/* eslint-disable import/no-extraneous-dependencies */
import ms from 'ms'
import jws from 'jws'
import {jwtStrategy, makeAuthMiddleware, sessionStrategy} from './index'
import {combineToAsync} from 'middleware-async'

const payload = {foo: {bar: 'baar'}, fooo: 1}
const makeJwtReq = (authHeader: string) => ({
	get: () => authHeader
})

describe('JWT strategy', () => {
	const secret = 'my secret'
	const {setPayload, getPayload} = jwtStrategy({secret})
	test('basic tests', () => {
		expect(setPayload()).toBe(undefined)
		const token = setPayload(undefined, payload)
		expect(typeof token).toBe('string')
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toEqual(payload)
		expect(getPayload(makeJwtReq(token))).toBeUndefined()
		expect(getPayload(makeJwtReq('Bearer 123'))).toBeUndefined()
		expect(getPayload(makeJwtReq('Bearer 123.456'))).toBeUndefined()
		expect(getPayload(makeJwtReq('Bearer 123.456.789'))).toBeUndefined()
	})
	test('incorrect secret', () => {
		const token = jwtStrategy({secret: '123'}).setPayload(undefined, payload)
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
	test('incorrect algorithm', () => {
		const token = jwtStrategy({secret, alg: 'HS384'}).setPayload(undefined, payload)
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
	test('different expire', () => {
		const token = jwtStrategy({secret, expire: ms('1 days')}).setPayload(undefined, payload)
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toEqual(payload)
	})
	test('expired', () => {
		const token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({payload, createdAt: new Date(Date.now() - ms('15 days')).toISOString()}),
			secret
		})
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
	test('malformed payload', () => {
		let token = jws.sign({
			header: {alg: 'HS256'},
			payload: 'an invalid json',
			secret
		})
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
		token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({createdAt: new Date()}),
			secret
		})
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
		token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({payload}),
			secret
		})
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
		token = jws.sign({
			header: {alg: 'HS256'},
			payload: JSON.stringify({payload, createdAt: 'an invalid date'}),
			secret
		})
		expect(getPayload(makeJwtReq(`Bearer ${token}`))).toBeUndefined()
	})
})

describe('Session Strategy', () => {
	const {getPayload, setPayload} = sessionStrategy()
	test('basic', () => {
		expect(setPayload({session: {}})).toBeUndefined()
	})
	describe('set', () => {
		test('remove payload', () => {
			const req = {session: {__auth: 123}}
			setPayload(req)
			expect(req.session.__auth).toBeUndefined()
		})
	})
	test('set and get', () => {
		const req = {session: {}}
		setPayload(req, payload)
		expect(getPayload(req)).toEqual(payload)
	})
	describe('get', () => {
		test('empty session', () => {
			expect(getPayload({session: {}})).toBeUndefined()
		})
		test('malformed session', () => {
			let req = {session: {__auth: 'an invalid auth session'}}
			expect(getPayload(req)).toBeUndefined()
			expect(req.session.__auth).toBeUndefined()
			req = {session: {__auth: 123}}
			expect(getPayload(req)).toBeUndefined()
			expect(req.session.__auth).toBeUndefined()
			req = {session: {__auth: {payload}}}
			expect(getPayload(req)).toBeUndefined()
			expect(req.session.__auth).toBeUndefined()
			req = {session: {__auth: {createdAt: new Date().toISOString()}}}
			expect(getPayload(req)).toBeUndefined()
			expect(req.session.__auth).toBeUndefined()
			req = {session: {__auth: {payload, createdAt: new Date(Date.now() - ms('15 days')).toISOString()}}}
			expect(getPayload(req)).toBeUndefined()
			expect(req.session.__auth).toBeUndefined()
		})
	})
})

describe('Authentication middleware', () => {
	const user = {id: 'user id', username: 'my username'}
	const encoder = ({id}) => Promise.resolve(id)
	const decoder = id => Promise.resolve(id === user.id ? user : undefined)
	test('with jwt strategy', async () => {
		const auth = makeAuthMiddleware(
			encoder,
			decoder,
			jwtStrategy({secret: 'my secret'})
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
		expect(req.user).toBeUndefined()
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
		expect(req.user).toBeUndefined()
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
