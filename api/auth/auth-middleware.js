const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({status: 401, message: "Token required"})
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
  if (err) {
    return next({status: 401, message: "Token invalid"})
  }
  req.decodedJwt = decoded
  next()
  })
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name !== role_name) {
    return next({status: 403, message: "This is not for you"})
  }
  next()
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body
  try {
    const [user] = await Users.findBy({username})
    if (!user) {
      next({status: 401, message: "Invalid credentials"})
    } else {
      req.user = {
        username: user.username,
        password: user.password,
        role_name: user.role_name,
        user_id: user.user_id,
      }
      next()
    }
  } catch (err) {
    next(err)
  }
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body
  if (!role_name || role_name === '') {
    req.body.role_name = 'student'
    return next()
  }
  else if (role_name === 'student' || role_name === 'instructor') {
    req.body.role_name = role_name.trim()
    return next()
  } 
  else if (role_name.trim() === 'admin') {
    return next({status: 422, message: "Role name can not be admin"})
  }
  else if (role_name.trim().length > 32) {
    return next({status: 422, message: "Role name can not be longer than 32 chars"})
  }
  req.body.role_name = role_name.trim()
  next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
