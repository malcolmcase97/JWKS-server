#JWKS Server

Created by Malcolm Case
For Professor Hochstetler
CSCE 3550.001
September 22, 2024

## Description

This project implements a JWKS server using Node.js and Express.

## Technology Stack
- **Language**: JavaScript (Node.js)
- **Libraries**:
  - Express: for building the web server
  - node-forge: for handling RSA key generation and PEM formatting
  - Jest: for testing

## Setup
1. Clone the repository:
    git clone https://github.com/malcolmcase97/JWKS-server.git
2. Navigate to directory
    cd /JWKS-server
3. Install dependencies
    npm install

## Running the Server
To start the server, use the following command:
npm start
The server will run on http://localhost:8080.

## Testing the Server
To run tests, use:
npm test

To check test coverage, use:
npm test -- --coverage
