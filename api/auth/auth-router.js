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
    res.status(200).json({ message: `${req.user.username} is back!`, token, subject: req.user.user_id})
  } else {
    next({ status: 401, message: "Invalid credentials"})
  }
});

module.exports = router;
