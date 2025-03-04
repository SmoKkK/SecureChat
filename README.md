# Secure Chat 

## Overview
This is a secure, real-time chat application built with Python (client) and Node.js (server). It features end-to-end encryption, user authentication, and both group and private messaging capabilities.

## Features
- **Secure Communication**: Messages are encrypted using AES-256 encryption
- **Real-time Messaging**: Instant message delivery using Socket.IO
- **User Authentication**: Secure login and session management
- **Group & Private Chats**: Both public group chats and private direct messages
- **Message History**: Stores and retrieves previous conversations
- **Cross-platform**: Works on Windows, macOS, and Linux

## Installation
### Server
1. Install Node.js
2. Run `npm install` in the server directory
3. Start the server with `node server.js`

### Client
1. Install Python 3.8+
2. Install requirements: `pip install -r requirements.txt`
3. Run the client: `python client.py`

## Usage
1. Start the server
2. Launch the client application
3. Enter your username and encryption key
4. Start chatting!

## Security Features
- AES-256 encryption for all messages
- Secure key exchange
- Message integrity verification
- Encrypted message storage

## License
[MIT License](https://opensource.org/licenses/MIT)
