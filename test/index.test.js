const chai = require('chai');
const expect = chai.expect;
const request = require('supertest');
const express = require('express');
const jwtLibFactory = require('../src/index');

const SECRET = 'test_secret';

describe('JWT Middleware Library', () => {
  let jwtLib;
  let app;

  beforeEach(() => {
    jwtLib = jwtLibFactory({
      secret: SECRET,
      excludePaths: ['/login'],
      signOptions: { expiresIn: '1h' },
    });

    app = express();
    app.use(express.json());
    app.use(jwtLib.middleware);

    // Protected route
    app.get('/protected', (req, res) => {
      res.status(200).json({ user: req.user });
    });

    // Unprotected route
    app.post('/login', (req, res) => {
      const token = jwtLib.createToken({ id: 1, username: 'testuser' });
      res.json({ token });
    });
  });

  it('should create a valid JWT token', () => {
    const token = jwtLib.createToken({ id: 123, role: 'admin' });
    expect(token).to.be.a('string');

    const decoded = require('jsonwebtoken').verify(token, SECRET);
    expect(decoded).to.have.property('id', 123);
    expect(decoded).to.have.property('role', 'admin');
  });

  it('should skip JWT verification on excluded path', async () => {
    const res = await request(app).post('/login');
    expect(res.status).to.equal(200);
    expect(res.body.token).to.be.a('string');
  });

  it('should allow access to protected route with valid token', async () => {
    const token = jwtLib.createToken({ id: 1, username: 'testuser' });

    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).to.equal(200);
    expect(res.body.user).to.include({ id: 1, username: 'testuser' });
  });

  it('should reject access to protected route with missing token', async () => {
    const res = await request(app).get('/protected');
    expect(res.status).to.equal(401);
    expect(res.body).to.have.property('error', 'Missing token');
  });

  it('should reject access with invalid token', async () => {
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer invalid.token.here`);

    expect(res.status).to.equal(403);
    expect(res.body).to.have.property('error', 'Invalid token');
  });
});