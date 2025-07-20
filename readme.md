### RSA Chat Application

This is a simple chat application that demonstrates RSA keys generation and encryption for secure communication.


=> When users want to connect, they will include both their public and private keys.
=> the public key will be sent to the server, and the private key will be stored locally.
=> the server will store the public keys of each user in a slice or User's structs.

=> when a message is sent, the server will encrypt the message using the systems AES generated Secret Key.
=> the server will then encrypt the AES secret key using the recipient's public key then send it to the recipient together with the encrypted message.

=> on the recipient's side, the client will decrypt the AES secret key using the recipient's private key.
then use the decrypt AES secret key to decrypt the message.

### CLI Application
The CLI application is an interface that will be used to generate both the private and public keys for Each Users.

=> For RSA keysgeneration, the application uses a random UUID as the seed for the random number generator.
