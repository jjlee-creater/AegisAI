const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
    app.use(
        '/api',
        createProxyMiddleware({
            target: 'http://http://15.164.13.20:8080/',
    changeOrigin: true,
})
);
};