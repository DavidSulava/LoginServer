var express = require('express');
var router = express.Router();
const formidable = require('express-formidable');

const auth = require('../controllers/auth.controller');

const {
  verifyAccessToken,
  resetTokens
} = require("../helpers/helpers");



/* Register User*/
router.post('/register', formidable(), auth.registerUser );
router.post('/login'   , formidable(), auth.login );


router.post('/logOut'      , verifyAccessToken, auth.logOut );
router.post('/newPassword' , [formidable(), verifyAccessToken], auth.updatePassword );
router.post('/updateUser'  , [formidable(), verifyAccessToken], auth.updateUser );
router.post('/updateAvatar', [formidable(), verifyAccessToken], auth.updateAvatar );

router.post('/email/confirmation'    , formidable(), auth.emailConfirm );
router.post('/email/sendVerification', [formidable(), verifyAccessToken], auth.emailVerify );


router.post('/get_new_tokens', resetTokens );

module.exports = router;
