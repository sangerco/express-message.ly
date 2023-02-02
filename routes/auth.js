const express = require('express');
const router = new express.Router();
const ExpressError = require('../expressError');
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config');
const { authenticateJWT, ensureLoggedIn, ensureCorrectUser } = require('../middleware/auth')
const User = require('../models/user')

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password are required", 400);
    }
    const login = await User.authenticate(username, password);
    if (login) {
      let token = jwt.sign({ username }, SECRET_KEY);
      User.updateLoginTimestamp(username);
      return res.json({ token });
    } else {
      throw new ExpressError("Invalid username/password", 400);
    }
  } catch (e) {
    return next(e);
  }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async (req, res, next) => {
  try { 
    const { username, password, first_name, last_name, phone } = req.body;
    if (!username || !password) {
      throw new ExpressError('Must provide username and password!', 400);
    }
    let token;
    const register = await User.register(username, password, first_name, last_name, phone);
    if(register) {
      token = await jwt.sign({ username }, SECRET_KEY);
      User.updateLoginTimestamp(username);
    }
    return res.json({token});
  } catch(e) {
    if(e.code === '23505') {
      return next(new ExpressError('Username taken, please pick another!', 400));
    }
    return next(e)
  }
})

module.exports = router;