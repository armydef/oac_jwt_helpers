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
    redirectTo = null
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
        return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      if(redirectTo)
        res.redirect(redirectTo);
      else  
        return res.status(401).json({ error: 'Missing token' });
    }

    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        if(redirectTo)
          res.redirect(redirectTo);
        else 
          return res.status(403).json({ error: 'Invalid token' });
      }
      req.user = decoded;
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