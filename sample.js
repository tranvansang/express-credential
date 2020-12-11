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
