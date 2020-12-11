import {combineToAsync} from 'middleware-async'
import connectAuthentication, {extractAndVerify} from '.'
import ms from 'ms'
import type {Request} from 'express'
import jws from 'jws'

const user = {id: '1', name: 'foo'}
const encode = async u => u.id
const decode = async id => id === '1' && user
const cookieKey = 'jwt'

const makeReq = (authHeader: string, cookie) => ({
	header() {
		return authHeader
	},
	cookies: {[cookieKey]: cookie}
}) as Request

describe('extract and verify', () => {
	const options = {
		alg: 'HS256',
		secret: '123',
		cookieKey
	}
	const expires = new Date(Date.now() + ms('7 days'))
	const makeToken = (val, exp, alg, secret) => jws.sign({
		header: {alg: alg || options.alg, expires: exp?.getTime()},
		payload: JSON.stringify(val),
		secret: secret || options.secret,
		encoding: 'utf8'
	})
	const payload = 1
	const token = makeToken(payload, expires)
	test('none algorithm', async () => {
		const tk = jws.sign({
			header: {alg: 'none'},
			payload: 1,
			secret: '123',
		})
		const btoa = val => Buffer.from(JSON.stringify(val)).toString('base64').replace(/=/g, '')
		expect(tk).toBe(`${btoa({alg: 'none'})}.${btoa(1)}.`)
		expect(tk).toBe('eyJhbGciOiJub25lIn0.MQ.')
	})
	const expectedResult = {
		payload,
		expires,
		token
	}
	test('normal run', async () => {
		expect(await extractAndVerify(makeReq(`Bearer ${token}`), options)).toEqual(expectedResult)
	})
	describe('token usage place', () => {
		test('use cookie', async () => {
			expect(await extractAndVerify(makeReq('bearer 1', token), options)).toEqual(expectedResult)
		})
		test('do not use any', async () => {
			expect(await extractAndVerify(makeReq('bearer 1', token), {...options, cookieKey: false})).toBeUndefined()
		})
		test('empty cookie', async () => {
			expect(await extractAndVerify(makeReq('bearer 1', ''), options)).toBeUndefined()
		})
	})
	describe('token encode/decode', () => {
		test('invalid token format', async () => {
			expect(await extractAndVerify(makeReq('Bearer 1'), options)).toBeUndefined()
		})
		test('token changes algorithm', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${makeToken(payload, expires, 'HS384')}`), options)).toBeUndefined()
		})
		test('token changes secret', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${makeToken(payload, expires, undefined, '456')}`), options)).toBeUndefined()
		})
		test('algorithm changes', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				options,
				alg: 'HS384'
			})).toBeUndefined()
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				options,
				alg: 'none'
			})).toBeUndefined()
		})
		test('secret changes', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				options,
				secret: '345'
			})).toBeUndefined()
		})
	})
	describe('token header validation', () => {
		test('no expires header', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${makeToken(payload)}`), options)).toBeUndefined()
		})
		test('invalid date format expires header', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${makeToken(payload, {
				getTime() {
					return 'invalid date'
				}
			})}`), options)).toBeUndefined()
		})
		test('expired token', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${makeToken(payload, new Date(Date.now() - 1))}`), options)).toBeUndefined()
		})
		test('revoked token', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				...options,
				isTokenRevoked() {
					return true
				}
			})).toBeUndefined()
			// async
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				...options,
				async isTokenRevoked() {
					return true
				}
			})).toBeUndefined()
		})
		test('non-revoked token', async () => {
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				...options,
				isTokenRevoked() {
					return false
				}
			})).toEqual(expectedResult)
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				...options,
				async isTokenRevoked() {
					return false
				}
			})).toEqual(expectedResult)
		})
	})
})

describe('connect-authentication factory', () => {
	const secret = '123'
	describe('middleware', () => {
		test('default options', async () => {
			const req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret))(req)
			expect(typeof req.login).toBe('function')
			expect(typeof req.logout).toBe('function')
			expect(req.user).toBeUndefined()
		})
		test('option is required', () => {
			expect(() => connectAuthentication(encode, decode, undefined)).toThrow('Secret is required')
			expect(() => connectAuthentication(encode, decode, secret, {
				alg: '1'
			})).toThrow('alg must be one of HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, none')
		})
	})

	describe('login', () => {
		test('returned token can be decoded', async () => {
			const req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret, {cookieKey: false}))(req)
			const token = await req.login(user)
			expect(await extractAndVerify(makeReq(`Bearer ${token}`), {
				secret,
				alg: 'HS256',
			})).toEqual({
				payload: await encode(user),
				expires: expect.any(Date),
				token
			})
		})
		test('login with cookie', async () => {
			const res = {cookie: jest.fn()}
			const req = makeReq('')
			const cookieOptions = {dump: 3}
			await combineToAsync(connectAuthentication(encode, decode, secret, {cookieOptions}))(req, res)
			const token = await req.login(user)
			expect(req.user).toBe(user)
			expect(res.cookie.mock.calls).toEqual([
				[
					cookieKey,
					token,
					{
						...cookieOptions,
						expires: expect.any(Date)
					}
				]
			])
		})
		test('login without cookie', async () => {
			const req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret, {cookieKey: false}))(req)
			await req.login(user)
			expect(req.user).toBe(user)
		})
	})

	describe('logout', () => {
		describe('cookie', () => {
			test('without cookie', async () => {
				const req = makeReq('')
				await combineToAsync(connectAuthentication(encode, decode, secret, {cookieKey: false}))(req)
				await req.logout()
				expect(req.user).toBeUndefined()
			})
			test('with cookie', async () => {
				const res = {clearCookie: jest.fn()}
				const req = makeReq('')
				const cookieOptions = {dump: 3}
				await combineToAsync(connectAuthentication(
					encode,
					decode,
					secret,
					{cookieOptions}
				))(req, res)
				await req.logout()
				expect(req.user).toBeUndefined()
				expect(res.clearCookie.mock.calls).toEqual([
					[
						cookieKey,
						{
							...cookieOptions,
							expires: undefined,
							maxAge: undefined
						}
					]
				])
			})
		})
		describe('revoke token', () => {
			const makeRevokeOptions = revokeToken => ({
				cookieKey: false, revokeToken
			})
			test('no need revoke if token is not set', async () => {
				const req = makeReq('')
				const revokeToken = jest.fn()
				await combineToAsync(connectAuthentication(
					encode,
					decode,
					secret,
					makeRevokeOptions(revokeToken)
				))(req)
				await req.logout()
				expect(req.user).toBeUndefined()
				expect(revokeToken.mock.calls.length).toBe(0)
			})
			test('no need revoke if token has already expired', async () => {
				const revokeToken = jest.fn()
				const token = jws.sign({
					header: {alg: 'HS256', expires: Date.now() - 1000},
					payload: JSON.stringify(encode(user)),
					secret,
				})
				const req = makeReq(`Bearer ${token}`)
				await combineToAsync(connectAuthentication(
					encode,
					decode,
					secret,
					makeRevokeOptions(revokeToken)
				))(req)
				await req.logout()
				expect(req.user).toBeUndefined()
				expect(revokeToken.mock.calls.length).toBe(0)
			})
			test('normal revoke', async () => {
				const revokeToken = jest.fn()
				const token = jws.sign({
					header: {alg: 'HS256', expires: Date.now() + ms('7 days')},
					payload: JSON.stringify(encode(user)),
					secret,
				})
				const req = makeReq(`Bearer ${token}`)
				await combineToAsync(connectAuthentication(
					encode,
					decode,
					secret,
					makeRevokeOptions(revokeToken)
				))(req)
				await req.logout()
				expect(req.user).toBeUndefined()
				expect(revokeToken.mock.calls).toEqual([
					[
						token,
						expect.any(Date)
					]
				])
			})
		})
	})
	describe('integration', () => {
		const options = {
			cookieKey: false
		}
		test('valid token', async () => {
			let req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret, options))(req)
			expect(req.user).toBeUndefined()
			const token = await req.login(user)
			req = makeReq(`Bearer ${token}`)
			await combineToAsync(connectAuthentication(encode, decode, secret, options))(req)
			expect(req.user).toBe(user)
		})
		test('valid token (string type ttl)', async () => {
			let req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret, {
				...options,
				ttl: '1 day'
			}))(req)
			expect(req.user).toBeUndefined()
			const token = await req.login(user)
			req = makeReq(`Bearer ${token}`)
			await combineToAsync(connectAuthentication(encode, decode, secret, options))(req)
			expect(req.user).toBe(user)
		})
		test('expired token', async () => {
			let req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret, {
				...options, ttl: -1000
			}))(req)
			expect(req.user).toBeUndefined()
			const token = await req.login(user)
			req = makeReq(`Bearer ${token}`)
			await combineToAsync(connectAuthentication(encode, decode, secret, options))(req)
			expect(req.user).toBeUndefined()
		})
		test('accept string type ttl', async () => {
			let req = makeReq('')
			await combineToAsync(connectAuthentication(encode, decode, secret, {
				...options, ttl: '-1 day'
			}))(req)
			expect(req.user).toBeUndefined()
			const token = await req.login(user)
			req = makeReq(`Bearer ${token}`)
			await combineToAsync(connectAuthentication(encode, decode, secret, options))(req)
			expect(req.user).toBeUndefined()
		})
	})
})
