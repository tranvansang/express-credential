# Authentication Middleware [![Build Status](https://travis-ci.org/tranvansang/connect-authentication.svg?branch=master)](https://travis-ci.org/tranvansang/connect-authentication)

[![NPM](https://nodei.co/npm/connect-authentication.png)](https://nodei.co/npm/connect-authenticationn/)

![Codecov block](https://codecov.io/gh/tranvansang/connect-authentication/branch/master/graphs/tree.svg)

Simple, production-level express (connect) middleware.

# How to install

- With `yarn`: `yarn add connect-authentication`.
- With `npm`: `npm install --save connect-authentication`.

# API

`makeAuthMiddleware(encoder, decoder, strategy)`: returns the connect-middleware for authentication.

- `encoder(user): Promise<IPayload>` (required): this function encodes user to a payload (to be stored in session or returned JWT).
Returned payload should be an object which can be serialized with `JSON.stringify`.
Because the returned payload can be exposed to client (with `jwtStrategy`), it should not contain secret information such as user password.
- `decoder(payload): Promise<IUser | void>` (required): takes the returned payload from `encoder`, returns the user data (or `undefined` if not found).
This returned data will be stored in server only.
It is safe to returned protected/secret data by this function.
- `strategy` (required): strategy returned by `sessionStrategy()` or `jwtStrategy()` or your own custom strategy.

`sessionStrategy(options)`: return a strategy based on server session.
This strategy requires [express-session](https://www.npmjs.com/package/express-session) to be installed.
- `options: {expire, key}` (optional, default: `{}`):
  + `expire: number` (optional, default: 14 days in milisec): the duration (in milisec) of a login session. Highly recommend [ms](https://www.npmjs.com/package/ms) package.
  + `key: string` (optional, default: `__auth`): the key used to store the login payload in `req.session`.


- `jwtStrategy(options)`: return a token-based strategy ([JSON Web Token](https://tools.ietf.org/html/rfc7519)).
This strategy assumes that the token is placed in the Authorization header of the request with `Bearer `(case sensitive) prefix.
Like `Authorization: Bearer <token>`.
  + `options: {secret, alg, expire}` (required)
  + `secret: string` (required): a securely random string, represent the secret for HMAC algorithm, or the PEM encoded public key for RSA and ECDSA. This secret will be passed to [jws's functions](https://github.com/brianloveswords/node-jws#jwsverifysignature-algorithm-secretorkey).
  + `alg: string` (optional, default `'HS256'`'): algorithm used to sign the payload. Supported algorithms: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`.
  Refer to [jws.ALGORITHMS](https://github.com/brianloveswords/node-jws#jwsalgorithms).
  + `expire: number` (optional, default 14 days in milisec): same as `sessionStrategy`.

After applying the middleware returned by `makeAuthMiddleware()`, there will be three properties added to the request `req`
- `req.user: IUser | undefined`: user data (returned by `decoder`) or `undefined` if user is not logged in (or with an invalid/expired credential).
- `req.login(user?: IUser)?: Promise<IToken>`: log the user in and (optionally) return a token. If user is `undefined` (or falsy), log out the current user.
- `req.logout()`: alias for `req.login(undefined)`

## Custom strategy

Custom strategy passed to `makeAuthMiddleware` must implement following interface

```typescript
interface IStrategy<IPayload, IToken> {
	setPayload: (req: Request, payload?: IPayload) => Promise<IToken | void> | IToken | void
	getPayload: (req: Request) => Promise<IPayload | void>
}
```

- `setPayload(req, payload)`: take the request and payload, optionally return a promise resolving a token.
This token will be resolved by `req.login()`.
- `getPayload(req)`: take a request and return a payload if exist.

# Usage example


```javascript
import express from 'express'
import {makeAuthMiddleware, jwtStrategy, sessionStrategy} from 'connect-authentication'
import session from 'express-session'
import bodyParser from 'body-parser'
import asyncMiddleware from 'middleware-async'

const app = express()
app.use(bodyParser.json(), session(), makeAuthMiddleware(sessionStrategy())) // in case of jwtStrategy, session() middleware is optional
app.post('/login', asyncMiddleware(async (req, res) => {
    const {body: {username, password}} = req
    const user = await findUser(username)
    if (user.comparePassword(password)) {
        await req.login(user)
        res.send('login success')//in case of jwtStrategy, response the client with the token returned by req.login().
    } else res.json('wrong credential')
}))
app.get('/user', (req, res) => {
//in case of jwtStrategy, the client must put the returned token from POST /login, in Authentication header with 'Bearer ' prefix.
    if (req.user) res.send(JSON.stringify(req.user))
    else res.send('user not logged in')
})
app.get('/logout', asyncMiddleware(async (req, res) => {
    await req.logout()
    res.send('user has been logged out')
}))
```
