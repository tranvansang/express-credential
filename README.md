# Authentication Middleware [![Build Status](https://travis-ci.org/tranvansang/connect-authentication.svg?branch=master)](https://travis-ci.org/tranvansang/connect-authentication)

# deprecated

[![NPM](https://nodei.co/npm/connect-authentication.png)](https://nodei.co/npm/connect-authenticationn/)

![Codecov block](https://codecov.io/gh/tranvansang/connect-authentication/branch/master/graphs/tree.svg)

A simple (opinionated) connect-style authentication middleware.

This middleware directly use [jws](https://www.npmjs.com/package/jws) package to implement a simpler version of [JsonWebToken](https://jwt.io/) to authenticate the users via cookie or the `Authentication` header.

Readers can read [the source code](./index.ts) to get the idea and replace the token encode/decode mechanism with [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken), or use this package directly.
This package does not follow [the standard of jsonwebtoken](https://tools.ietf.org/html/rfc7519).
However, it is well tested in it owns implementation.

## Usage sample

```javascript
const express = require('express')
const connectAuthentication = require('connect-authentication').default
const cookieParser = require('cookie-parser')
const asyncMiddleware = require('middleware-async').default
const bodyParser = require('body-parser')

const user = {id: '1', first: 'hello', last: 'world', username: 'admin'}
const encode = u => u.id
const decode = id => id === '1' && user
const app = express()
app.use(
		cookieParser('cookie-secret'),
		connectAuthentication(encode, decode, 'jws-secret')
)
app.get('/', (req, res) => res.status(200).send('hello world!'))
app.post('/login',
		bodyParser.json(),
		asyncMiddleware(async (req, res) => {
				const {body: {username, password}} = req
				if (username === 'admin' && password === 'password') {
						const token = await req.login(user)
						res.status(200).json(token)
				} else res.status(401).json({error: 'wrong credential'})
		})
)
app.get('/me', (req, res) => {
		if (req.user) res.status(200).json(req.user)
		else res.status(403).json({error: 'please login'})
})
app.get('/logout', asyncMiddleware(async (req, res) => {
		await req.logout()
		res.send('logout success')
}))
app.listen(3000, () => console.log('Server is listening at port 3000'))
```

## API Reference

Interface of the default export

```javascript
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
): RequestHandler
```
