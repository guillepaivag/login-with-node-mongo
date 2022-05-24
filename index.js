const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('./src/models/User')

const JWT_SECRET = 'f45645yerif2[]****][0iw4fasd54//1f8564g56d46.6469@4dcs6+5fc+sd9fsdf/*dsd+ff'

mongoose.connect('mongodb://localhost:27017/register-login')

const app = express()

app.use(express.json())

app.post('/api/change-password', async (req, res) => {
    const { body } = req
    const { authorization } = req.headers
    const { password } = body

    try {
        if (!authorization || typeof authorization !== 'string') {
            throw new Error('El usuario no está autenticado.')
        }

        let token = authorization && authorization.split(' ')[0] === 'Bearer' ?
            authorization.split(' ')[1] : null

        if (!token || typeof token !== 'string') {
            throw new Error('El usuario no está autenticado.')
        }
        
        if (!password || typeof password !== 'string') {
            throw new Error('La contraseña no es válida.')
        }

        const user = jwt.verify(token, JWT_SECRET)
        const _id = user.uid

        const passwordHash = await bcrypt.hash(password, 10)

        await User.updateOne({ _id }, {
            $set: { password: passwordHash }
        })

        res.status(200)
        res.send(user)
    } catch (error) {
        console.log('error', error)
        
        res.status(500)
        res.send({ error })
    }
    
})

app.post('/api/login', async (req, res) => {
    const { body } = req
    const { username, password } = body

    try {
        if (!username || typeof username !== 'string') {
            throw new Error('El nombre de usuario no es válido.')
        }

        if (!password || typeof password !== 'string') {
            throw new Error('La contraseña no es válida.')
        }

        const user = await User.findOne({ username }).lean()

        if (!user) {
            throw new Error('El nombre de usuario no existe.')
        }

        console.log('user', user)

        const isEquals = await bcrypt.compare(password, user.password)
        if (!isEquals) {
            throw new Error('La contraseña es incorrecta.')
        }

        const token = jwt.sign({
            uid: user._id,
            username: user.username
        }, JWT_SECRET)

        console.log('token', token)

        res.status(200)
        res.send({ token })
    } catch (error) {
        console.log('error', error)
        
        res.status(500)
        res.send({ error })
    }
    
})

app.post('/api/register', async (req, res) => {
    const { body } = req
    const { username, password } = body

    try {
        if (!username || typeof username !== 'string') {
            throw new Error('El nombre de usuario no es válido.')
        }

        if (!password || typeof password !== 'string') {
            throw new Error('La contraseña no es válida.')
        }

        if (password.length < 6) {
            throw new Error('La contraseña debe ser de al menos 6 carácteres.')
        }

        const passwordHash = await bcrypt.hash(password, 10)
        
        const result = await User.create({
            username,
            password: passwordHash
        })

        console.log('result', result)

        res.status(200)
        res.send({
            username,
            password,
            passwordHash,
            result,
        })
    } catch (error) {
        console.log('error', error)
        
        if (error.code === 11000) {
            console.log('Ya existe el usuario.')
        }

        res.status(500)
        res.send({
            error
        })
    }
    
})

app.listen(9999, () => {
    console.log(`http://localhost:9999`)
})