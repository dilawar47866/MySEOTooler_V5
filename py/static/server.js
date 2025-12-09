const express = require('express');
const path = require('path');
const app = express();

// 301 Redirect: www to non-www
app.use((req, res, next) => {
    if (req.headers.host === 'www.myseokingtool.com') {
        return res.redirect(301, 'https://myseokingtool.com' + req.url);
    }
    next();
});

// Serve static files from templates folder
app.use(express.static('templates'));

// Serve index.html for root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

// Start server
app.listen(process.env.PORT || 8080, () => {
    console.log('Server running on port', process.env.PORT || 8080);
});
