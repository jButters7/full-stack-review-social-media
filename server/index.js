//TODO Basic express setup
require('dotenv').config()
const express = require('express')
const session = require('express-session')
const massive = require('massive')
const authCtrl = require('./authController')
const postCtrl = require('./controller')
const verifyUser = require('./middlewares/verifyUser')

const app = express()

const { CONNECTION_STRING, SERVER_PORT, SESSION_SECRET } = process.env

app.use(express.json())
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 120 * 24 * 365 }
})
)

//#auth endpoints
//TODO login, register, logout, getUser
app.post('/auth/register', authCtrl.register)
app.post('/auth/login', authCtrl.login)
app.delete('/auth/logout', authCtrl.logout)
app.get('/auth/user', authCtrl.getUser)

//#posts endpoints
//TODO get post put delete posts
app.get('/api/posts', verifyUser, postCtrl.getPosts)
app.post('/api/posts', verifyUser, postCtrl.addPost)
app.put('/api/posts/:post_id', verifyUser, postCtrl.editPost)
app.delete('/api/posts/:post_id', verifyUser, postCtrl.deletePost)


massive({
  connectionString: CONNECTION_STRING,
  ssl: { rejectUnauthorized: false }
}).then(dbInstance => {
  app.set('db', dbInstance)
  console.log('DB is connected capn')
  app.listen(SERVER_PORT, () => console.log(`Crunchatize me on port ${SERVER_PORT}`))
})