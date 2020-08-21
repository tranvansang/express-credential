# Authentication Middleware [![Build Status](https://travis-ci.org/tranvansang/connect-authentication.svg?branch=master)](https://travis-ci.org/tranvansang/connect-authentication)

[![NPM](https://nodei.co/npm/connect-authentication.png)](https://nodei.co/npm/connect-authenticationn/)

![Codecov block](https://codecov.io/gh/tranvansang/connect-authentication/branch/master/graphs/tree.svg)

Simple, production-level express (connect) middleware.

# How to install

- With `yarn`: `yarn add connect-authentication`.
- With `npm`: `npm install --save connect-authentication`.

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

# API references

`import {makeAuthMiddleware, sessionStrategy, jwtStrategy} from 'connect-authentication'`

## `makeAuthMiddleware(encoder, decoder, strategy)`
Create a connect-middleware for authentication.

### Parameters:

- `encoder(user): Promise<IPayload>` (required): used to convert a native user object to a literal object which can be serialized with `JSON.stringify`.
Because the returned payload can be exposed to client (e.g., with the `jwtStrategy`), it should not contain secret information such as user password.
- `decoder(payload): Promise<IUser | void>` (required): takes the returned payload from `encoder`, returns the user data (or a falsy value if the payload is incorrect, or user is not found).
The returned data can be anything and can be seen in server only.
It is safe to returned protected/secret data by this function.
- `strategy: IStrategy<IPayload, IToken>` (required): strategy to store/restore/clear the payload.
This library comes with two strategies: `sessionStrategy()` and `jwtStrategy()`.

### Returned value

A connect-like middleware.

After the middleware returned by `makeAuthMiddleware()` is applied,
 there will be following properties added to the request `req` object.
- `req.user: IUser | undefined`: native user object (returned by `decoder`). `undefined` if user is not logged in (or logged in with an invalid/expired credential).
- `req.login(user: IUser)?: Promise<IToken> | IToken`: log the user in and return a token (by calling `strategy.setPayload()`).
If `user` is falsy, this function will do nothing.
- `req.logout()`: log out the user.

## `sessionStrategy(options)`
Create a session strategy.

### Parameters
This strategy requires [express-session](https://www.npmjs.com/package/express-session) to be installed and activated (via `req.use()`) before the middleware returned by `makeAuthMiddleware()` is applied.
- `options?: {key?: string}`: an optional options object which can have the following key.
  + `key?: string` (optional, default: `'__auth'`): the key used to store the login payload in `req.session` (by default, `req.session.__auth` is used).

### Returned value

An authentication strategy which can be passed to `makeAuthMiddleware()`.

## `jwtStrategy(options)`
Create a [JSON Web Token](https://tools.ietf.org/html/rfc7519) token-based strategy.

The strategy returned by this function assumes that the token is presented in the `'Authorization'` header of the request in the format `Bearer <token>` (case sensitive).
		
### Parameters
  + `options: {secret, alg, ttl, isTokenRevoked, revokeToken}` (required): a required options object which includes the following keys.
      + `secret: string` (required): a securely random string, represent the secret (for the HMAC algorithm), or the PEM encoded public key (for RSA and ECDSA).
      This secret will be passed to [jws's functions](https://github.com/brianloveswords/node-jws#jwsverifysignature-algorithm-secretorkey).
      + `alg: string` (optional, default `'HS256'`): algorithm used to sign the payload. Supported algorithms: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`.
      Refer to [jws.ALGORITHMS](https://github.com/brianloveswords/node-jws#jwsalgorithms) for the list of available algorithms.
      + `ttl: number` (required): token's Time To Live in milliseconds.
      + `isTokenRevoked?: (token: string) => Promise<boolean> | boolean` (optional): an optional function used to check whether a token is revoked before it expires.
      + `revokeToken?: (token: string, expire: Date) => Promise<void> | void` (optional): when `req.logout()` is called, this function (if exists) will be called to manually quarantine the generated token.
      `expire` is the timestamp specifying when the token will expire itself (and safely removed from the revoked token database).
      The most common scene is that `revokeToken` stores the revoked token into database (with a TTL), and `isTokenRevoked` check for a token validity by looking up for the token from database.

### Returned value

An authentication strategy which can be passed to `makeAuthMiddleware()`.

## Custom strategy

Custom strategy passed to `makeAuthMiddleware` must implement the following `IStrategy` interface.

```typescript
type Promisable<T> = T | Promise<T>

interface IStrategy<IPayload, IToken> {
	setPayload: (req: Request, payload: IPayload) => Promisable<IToken>
	getPayload: (req: Request) => Promisable<IPayload | undefined>
	clearPayload: (req: Request) => Promisable<void>
}
```

- `setPayload(req, payload)`: take the request and payload, return a token or a promise which resolves a token.
This token will become the result returned by `req.login()`.
- `getPayload(req)`: take a request and return a payload if exist.
- `clearPayload(req)`: clear the session information.
