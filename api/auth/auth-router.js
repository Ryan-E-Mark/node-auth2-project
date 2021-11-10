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


router.post("/login", checkUsernameExists, (req, res, next) => {
  const valid = bcrypt.compareSync(req.body.password, req.user.password)
  if (valid) {
    const token = buildToken(req.user)
    res.status(200).json({ message: `${req.user.username} is back!`, token})
  } else {
    next({ status: 401, message: "Invalid credentials"})
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
