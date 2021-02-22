
const bcrypt        = require("bcryptjs");
const userValidator = require('../DB/validators/userValidator')
const msg           = require('../customRespoce/msg');
const User_scm      = require('../DB/models/user.model');
const createError   = require('http-errors');

const {
    signAccessToken,
    signRefreshToken,
    verifyRefreshToken,
    revokeRefreshToken,
    userObject,
    sendEmail,
    cookieSettings
} = require("../helpers/helpers");

module.exports = {
    registerUser: async ( req, res, next ) => {
        try {

            // return res.json({ msg: process.env.MONGO_ATLAS_STR })
            let userEmail             = req.fields.email     ? req.fields.email                             : '';
            let firstName             = req.fields.firstName ? req.fields.firstName                         : '';
            let lastName              = req.fields.lastName  ? req.fields.lastName                          : '';
            let userPassword          = req.fields.password  ? req.fields.password                          : '';
            let password_confirmation = req.fields.password_confirmation ? req.fields.password_confirmation : '';


            let validateMessage = userValidator(userEmail, userPassword, password_confirmation);

            if (validateMessage)
                return res.status(401).json({
                    msg: validateMessage
                });

            let check = await User_scm.findOne({ email: userEmail });

            if ( check ) return res.status(401).json({ error: msg.ru.auth.userExist });

            //  ---------- [ variables for email authentication ] -------------
            let hostName = req.get('x-forwarded-host');
            let cTime    = Date.now() + (1000 * 60 * 15);
            let hash     = bcrypt.hashSync(`${ cTime }_${ userEmail }`, 8);

            let link     = `${hostName}/email/authentication/${userEmail}/${encodeURIComponent(hash)}`;


            let userPrepared = {
                email      : userEmail,
                firstName  : firstName,
                lastName   : lastName,
                isVerified : false
            }

            //--create user
            let user = new User_scm({
                ...userPrepared,
                password  : userPassword,
                token     : hash,
                timeToken : cTime
            });


            let savedUser = await user.save();

            if ( !savedUser ) throw createError.InternalServerError();

            let userPayload                 =  { ...userObject( user ), id: savedUser.id,  };
            let { refreshToken }            =  await signRefreshToken( userPayload );
            let { accessToken, expiresAt }  =  await signAccessToken( userPayload );


            //  ---------- [ send email ] -------------
            var html = `<div><p>Пожалуйста, пройдите по ссылке что бы подтвердить свой адрес эл.почты !</p> <a href='${link}'>Нажмите сдесь</a></div>`;

            await sendEmail(hostName, userEmail, 'email confirmation', html).catch(console.error);

            // --------- [ return Response] ---------------
            res.cookie("refreshToken", refreshToken, cookieSettings());

            return res.status(200).json({
                success: user.email + msg.ru.auth.regSuccess,
                user: {
                    ...userPrepared,
                    accessToken,
                    accessTokenExpiresAt: expiresAt,
                }
            });



        } catch (error) { next(error) }

    },
    login: async ( req, res, next )=>{
        try {

            let userEmail    = req.fields.email    ? req.fields.email    : '';
            let userPassword = req.fields.password ? req.fields.password : '';


            if ( !userEmail || !userPassword ) return res.status(401).send({ error:  msg.ru.auth.badCredentials });


            let user = await User_scm.findOne({  email: userEmail });

            if (!user) return res.status(401).send({ error:  msg.ru.auth.badCredentials });

            user.comparePassword(userPassword, async (err, callBack) => {

                if (err) return next( createError.InternalServerError() );

                if ( !callBack )
                    return res.status(401).send({ error:  msg.ru.auth.badCredentials });


                let userSaved  = await user.save();

                // error for testing purposes
                if ( !userSaved )
                    return next(createError.InternalServerError());

                let userPrepared = userObject(user)

                let { refreshToken }           = await signRefreshToken( userPrepared );
                let { accessToken , expiresAt} = await signAccessToken( userPrepared );

                res.cookie("refreshToken", refreshToken, cookieSettings());

                return res.status(200).send({
                    success: msg.ru.auth.success,
                    user: {
                        ...userPrepared,
                        accessToken : accessToken,
                        accessTokenExpiresAt: expiresAt,
                    },

                });

            })


        } catch (error) { next(error) }
    },
    logOut: async ( req, res, next )=>{
        try {

            if( !req.body.email ) throw createError.Unauthorized({ msg: msg.ru.badCredentials });

            let userEmail = req.body.email;

            let user = await User_scm.findOne({ email: userEmail });

            if ( user ) {

                if( !req.cookies['refreshToken'] ) throw createError.BadRequest();

                let refreshToken    = req.cookies["refreshToken"];
                let refTokenPayload = await verifyRefreshToken( refreshToken );

                await revokeRefreshToken( refTokenPayload.id );
            }

            return res.status(200).send({
                user: null
            });

        } catch (error) { next(error) }
    },
    updatePassword: async ( req, res, next )=>{

        try{
            let oldUserPassword = req.fields.password     ? req.fields.password     : '';
            let newUserPassword = req.fields.new_password ? req.fields.new_password : '';
            let userEmail       = req.fields.currentEmail;

            // -----------[ Change the Password ]---------------
            if ( !oldUserPassword || !newUserPassword )
                return res.status(401).send({ erPassword: msg.ru.auth.passwordMismatch });


            if( !userEmail ) throw createError.Unauthorized({ msg: msg.ru.badCredentials })

            let user = await User_scm.findOne({ email: userEmail });

            if ( !user ) return res.status(401).send({ error: msg.ru.auth.badCredentials });


            user.comparePassword(oldUserPassword, async (err, callBack) => {

                if (err) throw createError.InternalServerError();

                if ( !callBack ) {
                    return res.status(401).send({ erPassword: msg.ru.auth.wrongPassword });
                }

                user.password = newUserPassword;

                var newPasSaved = await user.save()

                if (!newPasSaved)  throw createError.InternalServerError();


                return res.status(200).send({
                   msg:{ passChanged: msg.ru.auth.passChanged }
                });
            });
        } catch (error) { next(error) }
    },
    updateUser: async ( req, res, next )=>{

        try{
            let userEmail    = req.fields.email     ? req.fields.email     : '';
            let firstName    = req.fields.firstName ? req.fields.firstName : '';
            let lastName     = req.fields.lastName  ? req.fields.lastName  : '';
            let userName     = req.fields.name      ? req.fields.name      : '';
            let userEmailOld = req.fields.currentEmail || '';

            let validateMessage = userValidator(userEmail);
            if (validateMessage)
                return res.status(201).send({
                    msg: validateMessage
                });

            // -----------[ Check if email not exists. Update Email ]--------------
            if ( userEmail != userEmailOld ) {

                let checkEmail = User_scm.find({
                    email: userEmail
                })

                if ( checkEmail )
                    return res.status(401).send({
                        msg: {
                            emailErr: 'A user with such email already exists!'
                        }
                    });
            }


            let user = await User_scm.findOne({
                email: userEmailOld
            });

            if ( !user ) return res.status(401).send({ error: msg.ru.auth.badCredentials });

            user.email      = userEmail;
            user.isVerified = userEmail != userEmailOld ? false: user.isVerified;
            user.firstName  = firstName;
            user.lastName   = lastName;
            user.name       = userName;

            let isSaved = await user.save();
            if ( isSaved ) {

                userPrepared = userObject(user);

                return res.status(200).send({
                    msg : { userUpdated: msg.ru.auth.userUpdated },
                    user: { ...userPrepared },
                });
            }
        }catch(error) { next(error) }
    },
    updateAvatar: async( req, res, next )=>{
        try {

            if( !req.fields.img ) return res.status(201).send({ msg: { imgError: 'no image selected'} });

            let userAvatar = req.fields.img ? req.fields.img : '';
            let userEmail  = req.accessTokenPayload.email;

            let user = await User_scm.findOne({
                email: userEmail
            });

            if ( !user ) return res.status(401).send({ error: msg.ru.auth.badCredentials });

            user.img = userAvatar;
            let userSaved = await user.save();

            if ( userSaved ) {

                let userPrepared = userObject(userSaved);

                return res.status(200).send({
                    msg : { avatarUpdated: 'Avatar successfully updated !' },
                    user: { ...userPrepared },
                });
            }

            next();
        } catch (error) { next(error) }

    },
    emailConfirm: async ( req, res, next )=> {

        try{
            let token = req.fields.token ? decodeURIComponent(req.fields.token) : '';
            let email = req.fields.email ? req.fields.email : '';
            let cTime = Date.now();

            if( !email || !token )
                return res.status(401).send({
                    msg: {
                        errorCred: msg.ru.auth.badCredentials
                    }
                });


            let user = await User_scm.findOne({
                email: email
            });

            if( user.isVerified ) return res.status(200).send({
                msg : { emailConfirmed : msg.ru.email.emailConfirmed },
                user: { ...userObject(user) }
            })


            if ( !user || user.token != token || user.email != email ||  cTime > user.timeToken )
                return res.status(401).send({
                    error: msg.ru.auth.badCredentials
                });

            user.isVerified = true;
            let isSaved = await user.save();

            if ( !isSaved )
                return res.status(401).send({
                    msg: {
                        timeErr: msg.ru.email.confEr
                    }
                });


            return res.status(200).send({
                msg : {
                    emailConfirmed : msg.ru.email.emailConfirmed
                },
                user: {
                    ...userObject(user),
                }
            });

        }catch(error){ next(error) }
    },
    emailVerify: async ( req, res, next )=> {

        try{
            let userEmail = req.fields.email ? req.fields.email : '';

            let validateMessage = userValidator( userEmail );

            if (validateMessage)
                return res.status(401).json({
                    msg: validateMessage
                });

            // -----------[ Check and Update Email ]--------------

            let user = await User_scm.findOne({ email: userEmail })

            if ( !user )
                return res.status(401).send({
                    msg: {
                        emailErr: msg.ru.auth.badCredentials
                    }
                });

            let hostName = req.get('origin');
            let cTime    = Date.now() + (1000 * 60 * 15);
            let hash     = bcrypt.hashSync(`${ cTime }_${ userEmail }`, 8);
            let link     = `${hostName}/email/authentication/${userEmail}/${encodeURIComponent(hash)}`;
            let html     = `<div><p>Please click the link below to confirm your email !</p> <a href='${link}'>Click Here</a></div>`;

            // --- change data in database

            user.token      = hash;
            user.timeToken  = cTime;
            user.isVerified = false;

            let dataSaved = await user.save();

            if (dataSaved) {
                //  ---------- [ send email confirmation link ] -------------
                await sendEmail(hostName, userEmail, 'email confirmation', html).catch(console.error);

                userPrepared = userObject(user)


                return res.status(200).send({
                    msg: { verLinkSend: `Verification link has been sent to ${ user.email }` },
                    user: {
                        ...userPrepared,
                    }
                });
            }
        }catch(error){ next(error) }

    },
}