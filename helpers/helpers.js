const nodemailer = require("nodemailer");
var JWT = require('jsonwebtoken');
const createError = require('http-errors');
const {Promise} = require("mongoose");

const msg = require('../customRespoce/msg');

const Token_scm = require('../DB/models/token.model');


/**
 * *Table of contents
 *
 * -- JWT token Helper Functions Section --
 * ----------------------------------------
 * *signAccessToken()
 * *signRefreshToken()
 * *verifyAccessToken()
 * *verifyRefreshToken()
 * *resetTokens()
 * *revokeRefreshToken()
 *
 * -- Helper Section --
 * ----------------------------
 * *userObject()
 * *cookieSettings()
 * *sendEmail()
 * *serverError()
 * addTime()
 */


//----- [ JWT token Helper Functions Section ] -----
const signAccessToken = (userObject) => {

    return new Promise((resolve, reject) => {

        const options = {
            expiresIn: process.env.JWT_ACCESS_EXPIRES,
        }

        JWT.sign(userObject, process.env.JWT_ACCESS_SECRET, options, (err, token) => {

            if (err)
                reject(createError.InternalServerError());

            let expiresAt = Date.now() + eval(process.env.JWT_ACCESS_EXPIRES_MS) - (1000 * 60 * 1);
            resolve({accessToken: token, expiresAt});
        })
    })
}
const signRefreshToken = (userObject) => {

    return new Promise((resolve, reject) => {

        const payload = userObject;
        const options = {
            expiresIn: process.env.JWT_REFRESH_EXPIRES,
        }

        JWT.sign(payload, process.env.JWT_REFRESH_SECRET, options, async (err, token) => {

            if (err)
                reject(createError.InternalServerError());


            let makeToken = new Token_scm({
                id: userObject.id,
                refreshToken: token,
            });

            let isTokenSaved = await makeToken.save()

            if (!isTokenSaved)
                reject(createError.InternalServerError());

            let expiresAt = new Date(isTokenSaved.createdAt).getTime() + eval(process.env.JWT_REFRESH_EXPIRES_MS) - (1000 * 60 * 1);

            resolve({refreshToken: token, expiresAt});
        })
    })
}
const verifyAccessToken = (req, res, next) => {

    if (!req.headers['authorization']) return next(createError.Unauthorized())

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1].trim();

    JWT.verify(token, process.env.JWT_ACCESS_SECRET, (err, payload) => {

        if (err) throw createError.Unauthorized();

        req.accessTokenPayload = payload
        next()
    })
}
const verifyRefreshToken = (refreshToken) => {

    return new Promise((resolve, reject) => {

        JWT.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, payload) => {

                if (err) return reject(createError.Unauthorized());

                let token = await Token_scm.findOne({
                    refreshToken: refreshToken
                });

                if (!token) return reject(createError.Unauthorized({msg: msg.ru.badCredentials}));
                if (!token.refreshToken || token.refreshToken !== refreshToken) return reject(createError.Unauthorized());

                resolve(payload);
            }
        )
    })
}
const resetTokens = async (req, res, next) => {
    try {

        if (!req.cookies.refreshToken) throw createError.BadRequest();

        const refreshTokenOld = req.cookies.refreshToken;

        const payload = await verifyRefreshToken(refreshTokenOld)
        const userObj = userObject(payload);

        const {accessToken, expiresAt} = await signAccessToken(userObj);
        const {refreshToken} = await signRefreshToken(userObj);

        res.cookie("refreshToken", refreshToken, cookieSettings());

        res.send({accessToken, accessTokenExpiresAt: expiresAt});

    } catch (error) {
        next(error)
    }
}
const revokeRefreshToken = async (refreshTokenId) => {

    return new Promise(async (resolve, reject) => {

        let token = await Token_scm.deleteMany({
            id: refreshTokenId
        }).catch(error => {

            console.log(error);
            reject(createError.InternalServerError())
        });

        resolve(token);
    })


}
//----- [ Helper Section ] -----
const userObject = (data) => {

    return {
        id: data._id || data.id && data._id || data.id,
        email: data.email && data.email,
        name: data.name && data.name,
        firstName: data.firstName && data.firstName,
        lastName: data.lastName && data.lastName,
        isVerified: data.isVerified && data.isVerified,
        img: data.img && data.img
    }
}
const cookieSettings = () => {

    if (process.env.NODE_ENV && process.env.NODE_ENV === 'development')
        return {httpOnly: true}

    return {httpOnly: true, secure: true, sameSite: 'None'}
}
const sendEmail = async function (From, ToEmail, subject, html) {

    // create reusable transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465, // 587, 465
        secure: true, // true for 465, false for other ports
        auth: {
            type: 'OAuth2',
            user: process.env.CONTACT_EMAIL,
            clientId: process.env.CONTACT_CLIENT_ID,
            clientSecret: process.env.CONTACT_SECRET,
            refreshToken: process.env.CONTACT_REFRESH_TOK,

        }
    });

    // send mail with defined transport object
    await transporter.sendMail({
        from: `${From} <webproto3@gmail.com>`, // sender address
        to: ToEmail, // list of receivers
        subject: subject, // Subject line
        html: html // html body
    });

}
//TODO: this is only a crutch. Has to be improved
const serverError = function (error, res, at_where = '') {

    console.error(`-*- something went wrong at ${at_where} -*-`, error);

    return res.status(500).json({
        msg: {
            server_error: `something went wrong at ${at_where}`
        }
    });

}
// ? maybe i will use it later
// passed variable type is string: '1000 * 60 * 12'
const addTime = (addedTime) => {
    return Date.now() + addedTime;
}

module.exports = {
    signAccessToken,
    signRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
    resetTokens,
    revokeRefreshToken,
    userObject,
    sendEmail,
    serverError,
    addTime,
    cookieSettings
}