const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const buildToken = require('./token-builder')

router.post("/register", validateRoleName, async (req, res, next) => {
  let user = req.body

  const hash = bcrypt.hashSync(user.password, 6)
  user.password = hash
  try {
    const newUser = await Users.add(user)
    res.status(201).json(newUser)
  } catch (err) {
    next(err)
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  let { username, password } = req.body
  try {
    const user = await Users.findBy({username})
    const validPassword = bcrypt.compareSync(password, user.password)
    if (!validPassword) {
      return next({status: 401, message: "Invalid credentials"})
    }
    const token = buildToken(user)
    res.status(200).json({message: `${user.username} is back!`, token})
  } catch (err) {
    next(err)
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
