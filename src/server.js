'use strict';
const { config, validate } = require('./config');

const problems = validate();
if (problems.length) {
  console.error('\nCannot start — fix these in your .env file:\n  - ' + problems.join('\n  - ') + '\n');
  process.exit(1);
}

const { createApp } = require('./app');
const server = createApp();
server.listen(config.port, () => console.log(`Ethio Exam API listening on port ${config.port} (${config.isProd ? 'production' : 'development'})`));

function shutdown() { console.log('Shutting down…'); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
