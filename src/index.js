const jwt = require('jsonwebtoken');

/**
 * Creates JWT middleware with configurable options.
 *
 * @param {Object} options
 * @param {string} options.secret - The JWT secret key.
 * @param {string[]} [options.excludePaths] - Paths to exclude from verification.
 * @returns {function} Express middleware function.
 */
module.exports = function createJwtMiddleware({ 
    secret, 
    excludePaths = [],
    signOptions = { expiresIn: '1h' },
    redirectTo = null,
    useCookie = true
}) {
  if (!secret) {
    throw new Error('JWT secret is required');
  }

  function middleware(req, res, next) {
    // Skip verification if the path matches any excluded path
    if (excludePaths.some((path) => {
        if (typeof path === 'string') {
            return path === req.path;
        }
        if (path instanceof RegExp) {
            return path.test(req.path);
        }
        return false;
    })) {
        console.log("Path is public => next()")
        return next();
    }

    console.log("JwtMiddleware: step 1")
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    if(!token && useCookie && req.cookies) token = req.cookies.token;

    console.log("JwtMiddleware: step 2")
    if (!token) {
      if(redirectTo)
        return res.redirect(redirectTo);
      else  
        return res.status(401).json({ error: 'Missing token' });
    }

    console.log("JwtMiddleware: step 3")
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        if(redirectTo)
          return res.redirect(redirectTo);
        else 
          return res.status(403).json({ error: 'Invalid token' });
      }
      req.user = decoded;

      console.log("JwtMiddleware: step 4")
      if(useCookie){
        newToken = createToken({ user: decoded.user })
        console.log("JwtMiddleware: " + newToken)
        res.cookie('token', newToken, {
          httpOnly: true,
          secure: false,
          sameSite: 'lax'
        })
      }
      console.log("JwtMiddleware: step 5")
      next();

    });
  };


  function createToken(payload, options = {}) {
    return jwt.sign(payload, secret, { ...signOptions, ...options });
  }

  return {
    middleware,
    createToken,
  };

};