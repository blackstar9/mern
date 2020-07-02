const { Router } = require('express')
const bcrypt = require('bcryptjs') 
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')

const router = Router()

// /api/auth/register
router.post(
    '/register', 
    [
        check('email', 'Wrong email').isEmail(),
        check('password', 'Minimal lenght')
        .isLength({min: 6})
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if(!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Uncorrect data'
            })
        }

        const {email, password} = req.body

        const candidate = await User.findOne({email})

        if(candidate){
            return res.status(400).json({message: 'Such user already exists'})
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({email, password: hashedPassword})

        await user.save()

        res.status(201).json({message: 'User created'})

    } catch (error) {
        res.status(500).json({message: 'Error'})
    }
})

// /api/auth/login
router.post(
    '/login', 
    [
        check('email', 'Wrong email').normalizeEmail().isEmail(),
        check('password', 'Enter pasword').exists()
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if(!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Uncorrect data'
            })
        }

        const {email, password} = req.body

        const user = await User.findOne({email})

        if(!user){
            res.status(500).json({message: 'Something go wrong'})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch){
            return res.status(400).json({message: 'Uncorrect password'})
        }

        const token = jwt.sign(
            {userId: user.id},
            config.get('jwtSecret'),
            {expiresIn: '1h'}
        ) 

        res.json({token, userId: user.id})
       
    } catch (error) {
        res.status(500).json({message: 'Error 1'})
    }
})

module.exports = router