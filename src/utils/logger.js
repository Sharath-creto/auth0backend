const winston = require('winston');
const path = require('path');

const logDirectory = path.join(__dirname, 'logs');

// Ensure the log directory exists
require('fs').mkdirSync(logDirectory, { recursive: true });

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
  ),
  transports: [
    new winston.transports.File({ filename: path.join(logDirectory, 'combined.log') }),
    new winston.transports.File({ filename: path.join(logDirectory, 'error.log'), level: 'error' })
  ]
});

module.exports = logger;
