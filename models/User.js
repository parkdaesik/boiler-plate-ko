const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10

const userSchema = mongoose.Schema({
    name:{
        type: String,
        maxlength:50
    },
    email: {
        type:String,
        trim: true,
        uniqure:1
    },
    password: {
        type: String,
        minlength:5
    },
    lastname: {
        type:String,
        maxlength: 50
    },
    role: {
        type:Number,
        default:0
    },
    image: String,
    token: {
        type:String
    },
    tokenExp:{
        type:Number
    }
})

userSchema.pre('save', function( next ) {

    var user = this;



    //비밀번호를 암호화 시킴.
    bcrypt.genSalt(saltRounds, function(err, salt){
        if(err) return next(err)

        if(user.isModified('password')) {

        bcrypt.hash(user.password , salt, function(err, hash) {
            if(err) return next(err)
            user.password=hash //유저 비밀번호를 암호화된 비밀번호로 변경.
        })

    }
    })


    next()

     

})

const User = mongoose.model('User', userSchema)

module.exports = { User }