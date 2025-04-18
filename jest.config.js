module.exports = {
  testEnvironment: 'node',
  coverageDirectory: 'coverage',
  collectCoverage: true,
  collectCoverageFrom: ['**/*.js', '!**/node_modules/**', '!**/coverage/**', '!**/jest.config.js'],
  setupFiles: ['dotenv/config'], // Load environment variables from .env file
};
