require("dotenv").config();
const express = require('express');
const cookieParser = require('cookie-parser');
const csurf = require('xsrf');
const jwtcrypt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const rateLimit = require('express-rate-limit')
//const csrfProtection = csurf({ cookie: true });

// Create a new router
const DefaultRouter = express.Router();

// Middleware to parse cookies
DefaultRouter.use(cookieParser());
DefaultRouter.use(express.json());
// CSRF protection middleware
const csrfProtection = csurf({ cookie: true });

// Rate limiting middleware
const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 5 requests per windowMs
    message: 'Too many refresh requests from this IP, please try again after 15 minutes',
});

const authMiddleware = (req, res, next) => {
    console.log('begining authMiddleware......... + route: ', req.route.path);
    //refreshToken(req, res, next);
    //console.log('headers authMiddleware: ', req.headers.cookie);
    const accessToken = req.cookies.accessToken;
    //const refreshToken = req.cookies.refreshToken;
    if (!accessToken) {
        console.log('access token not found: ');
        //refreshToken(req, res, next);
        return res.status(401).send('Unauthorized');
    }
    //console.log('accessToken: ', accessToken);
    jwtcrypt.verify(accessToken, process.env.ACCESS_TOKEN, (err, decoded) => {
        if (err) {
            return res.status(401).send('Unauthorized');
        }
        console.log('decoded authMiddleware: ', decoded);
        next();
    });
};
const protectRefresh = (req, res, next) => {
    console.log('begining protectRefresh....... + route: ', req.route.path);
    //refreshToken(req, res, next);
    //console.log('headers authMiddleware: ', req.headers.cookie);
    const refreshToken = req.cookies.refreshToken;
    //const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        console.log('refresh token not found: ');
        //refreshToken(req, res, next);
        return res.status(403).send('Unauthorized');
    }
    //console.log('accessToken: ', refreshToken);
    jwtcrypt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, decoded) => {
        if (err) {
            return res.status(403).send('Unauthorized');
        }
        console.log('decoded refreshtoken protectRefresh : ', decoded);
        next();
    });
};
// // Route to get CSRF token
DefaultRouter.route('/csrf').get(csrfProtection, (req, res) => {
    //console.log('CSRF token sent: ', req.csrfToken());
    res.json({ csrfToken: req.csrfToken() });
});


// Example login route
DefaultRouter.route('/login').post(csrfProtection, refreshLimiter, async (req, res) => {
    const post = req.body;
    const { username, password } = req.body;
    if (username === 'alin.neaga') {
        //console.log('process.env.secret: ', `${process.env.JWT_SECRET_KEY}`);
        const accessToken = jwtcrypt.sign({ username: username }, `${process.env.ACCESS_TOKEN}`, { expiresIn: 3 * 1000, });
        //console.log('accessToken login: ', accessToken);
        const refreshToken = jwtcrypt.sign({ username: username }, `${process.env.REFRESH_TOKEN}`, { expiresIn: 1 * 12 * 60 * 60 * 1000, });
        res.cookie('accessToken', accessToken, { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 3 * 1000 });
        res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 1 * 12 * 60 * 60 * 1000 });
        res.status(200).send({ 'data:': post });
    } else {
        res.status(401).send({ 'data:': post });
    }
    //res.status(200).send({ 'Data from LOGIN is being processed:': post });
});
//get refresh token
DefaultRouter.route("/refresh").post(csrfProtection, refreshLimiter, protectRefresh, async (req, res) => {
    console.log('begining refresh endpoint........... + route: ', req.route.path);
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);

    jwtcrypt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
        if (err) return res.sendStatus(403);
        //console.log('user decoded refreshToken:', user);
        const accessToken = generateAccessToken({ username: user.username });
        res.cookie('accessToken', accessToken, { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 3 * 1000 })
            .json({ token: accessToken }); // 3 seconds
        //res.json({ message: 'Access token refreshed' });
    });
});
function generateAccessToken(user) {
    return jwtcrypt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '3s' });
}
function generateRefreshToken(user) {
    return jwtcrypt.sign(user, process.env.REFRESH_TOKEN, { expiresIn: '12h' });
}
//Verify protected page
DefaultRouter.route('/protected').post(csrfProtection, refreshLimiter, authMiddleware, async (req, res) => {
    const post = req.body;
    res.status(200).send({ post });
});

// Example protected route
DefaultRouter.route('/testing').post(csrfProtection, authMiddleware, async (req, res) => {
    const post = req.body;
    res.status(200).send({ post });
});
// Example protected route
DefaultRouter.route('/logout').get(csrfProtection, authMiddleware, async (req, res) => {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).send({ message: 'Logged out' });
});
// Error handling middleware
DefaultRouter.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        res.status(403).send('Invalid CSRF token');
    } else {
        next(err);
    }
});

// Export the router
module.exports = DefaultRouter;