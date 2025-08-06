### RSA Chat Application

This is a simple chat application that demonstrates RSA keys generation and encryption for secure communication.

=> When users want to connect, they first generate their public and private keys then key in their token {for demo purposes Alice's token is 'a' and Bobs token is 'b'}.
=> the public key will be sent to the server, and the private key will be stored locally.
=> the server will store the public keys of each user in the User's structs.

=> when a message is sent, the server will encrypt the message using the systems AES generated Secret Key.
=> the server will then encrypt the AES secret key using the recipient's public key then send it to the recipient together with the encrypted message.

=> on the recipient's side, the client will decrypt the AES secret key using the recipient's private key
then use the decrypted AES secret key to decrypt the message using forge library https://github.com/digitalbazaar/forge.

## Features
==> The RSA key-pair is generated from the FE using the Generate RSA keys button on the FE which sends an API request to the server.
==> For RSA keysgeneration imitates Java's SecureRandom by using custom random UUID as the seed for the random (p and q) generators. [not recommedd for prod]

## Running the Application
On the root of the project run `go run .` to start both the rest API and Websocket on port 8080.
It should log something similar to

```
2023/05/20 14:30:00 Starting server on  :8080
```

Then visit your index.html on the browser to interact with the application.

### CLI Application
The CLI application is also included in the project that acts technically like openssl generate RSA keypair.
