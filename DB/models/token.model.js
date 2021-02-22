const mongoose = require('mongoose');

const expTime = eval( process.env.JWT_REFRESH_EXPIRES_MS );

const tokenSchema = new mongoose.Schema(
    {
        id           : { type : String, required: true },
        refreshToken : { type : String, required: true },
    },
    { timestamps: true }
);
// tokenSchema.index({ expire_at    : { type: Date, default: Date.now, expires: expTime } });
tokenSchema.index( { createdAt:1 }, { expireAfterSeconds: expTime } );

const Token_scm =  mongoose.model( 'refreshtokens', tokenSchema ) ;

module.exports  = Token_scm;