require("dotenv").config();
const express = require('express');
// const cookieParser = require('cookie-parser');
// const csurf = require('csurf');
const cors = require('cors');
const DefaultRouter = require('./routes/index');
const app = express();
const port = 3000;
const URL_CLIENT = process.env.URL_CLIENT // || process.env.URL_CLIENT_PROD;
// Enable CORS for all routes
app.use(cors({
    origin: URL_CLIENT, // Replace with your Vue app's URL
    credentials: true,
}));

// Middleware to parse cookies
//app.use(cookieParser());

// CSRF protection middleware
//const csrfProtection = csurf({ cookie: true });

// Middleware to parse JSON bodies
app.use(express.json());

// // Route to get CSRF token
// app.get('/csrf', csrfProtection, (req, res) => {
//     console.log('CSRF token sent: ', req.csrfToken());
//     res.json({ csrfToken: req.csrfToken() });
// });

// // Example protected route
// app.post('/submit', csrfProtection, (req, res) => {
//     const post = req.body;
//     res.status(200).send({
//         'Data submited for testing is being processed:': post
//     });
// });

// // Example protected route
// app.post('/login', csrfProtection, (req, res) => {
//     const post = req.body;
//     res.status(200).send({ 'Data from LOGIN is being processed:': post });
// });


// // Error handling middleware
// app.use((err, req, res, next) => {
//     if (err.code === 'EBADCSRFTOKEN') {
//         res.status(403).send('Invalid CSRF token');
//     } else {
//         next(err);
//     }
// });

app.use('/api', DefaultRouter);

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});