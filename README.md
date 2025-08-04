# Cyber-Security-Mini-Programs
Folder containing simple cyber security progamming exercises.

## Password-Strength-Validator
Simple program written in python in combination with tkinter for the GUI. It takes in a password inputted by a user and checks the strength based on certain criteria.

Located Here: ([Password-Strength-Tester](./Password-Strength-Validator/PasswordChecker.py))

<p align="center">
  <img src="./Project-Images/password-strength-tester.png" alt="Password Strength Tester" />
</p>

### Password Criteria
- Unique set of lowercase characters accounts for a point.
- Unique set of uppercase characters accounts for 2 points.
- Unique set of numbers accounts for 2 points.
- Unique set of special characters accounts for 3 points.
- For every 8 charcters in a password you get a point.
- For every diverse type of character acquire 2 points getting a potential extra 8 points.
- If the password cointains a common phrase then penalise 3 points of score with a max penatly of 20.

### Reasons For Criteria
Having unique sets of characters and diverse set of characters helps improve complexity against brute force password attacks.

### Common Password Phrases
Used a file containing 10,000 common phrases frequently found in passwords. These phrases are penalized during password evaluation, as they are vulnerable to dictionary attacks and significantly reduce password security.

### Scores
Below shows how each score is interpreted in the code.
```python
    if score < 8: return "Very Weak"
    elif score < 18: return "Weak"
    elif score < 25: return "Moderate"
    elif score < 30: return "Strong"
    else: return "Very Strong"
```
## Crypt-Socket
SImple Client-Server Socket program that allows users to message each other securley. This was done to teach myself about simple principles of Cryptography.

## Running Crypt-Socket
In order to run you need to have Python 3.

In your terminal switch to directory ([Crypt-Socket](./Crypt-Socket/))

First run server module of program by writing this command.
```
  python3 -m server.server
````

Then to run client program write this command.
```
  python3 -m client.client
```

### Explanation of what it does
---
This section will cover what is actually being done behind the scenes.

### Registration
- Checks with server if a username exists within the server by hashing the username inputted and encrypting it with the server public key.
- If username doesn't exist then generate a RSA key pair and save it locally.
- Create user json that server can use to store newly created user (inputted password is also hashed when creating this json).
- Generate a temporary AES registration key and send to server by encrypting with server public key.
- Encrypt user data with registration key and send to server.
- Server process data and stores it and generates a user certificate and sends it back to the client.
- At this point registration is now complete.

### Login
- Checks with server if a username exists and then checks if the inputted plaintext password (which is encrypted using the server public key) and check if it matches the hashed one on the server associated with that user.
- After the check the server issues a nonce which is encrypted using users public key.
- Client then decrypts nonce and signs it.
- Client also loads their certificate at the same time.
- Client prepares a payload that includes their certificate along with the nonce and the signed nonce and esnds it over to the server.
- Server then checks if the certificate is valid which if it is grabs the users public key from the certificate and verifies the signed nonce against the nonce sent.
- Server checks if the nonce is valid and if it is the user is authenticated and the server prepares to generate user infromation to be sent over.
- Server generates a session key that will be shared for the current session which is sent to the client encrypted using their public key derived from certificate.
- Client recieves and decrypts session key and stores it.
- Server encrypts the user information with session key and sends to client.
- Client then decrypts it and stores information locally and is now logged in.

### Send Messages
- Client enters username of user they want to message and checks with the server if they exist and if so continues.
- Client prompted to enter the message they want to send.
- After the message contents is hashed and signed by user private key.
- A temp AES message key is created that is used to encrypt the signed data and plaintext message content.
- The temp AES key is then encrypted with the receivers public key.
- Client prepares a message payloadm and encrypts it with shared session key and sends it to server.
- Server then decrypts and process' the payload and checks who the receiver of the message is and then adds the message to receivers queue.
- Server then sends a flag to indicate to the user the message has been sent.
- If the receiver is currently logged in the server will send the message payload over to the receiver encrypted via the shared session key between them and then a message for the receiver will print saying they received a new message.

### Read Messages
- Client sends a flag to let the server know they are reading the message queue they have by sending over the hashed username.
- Server finds the user and makes their message queue empty.
- Client loads their messages and decrypts the AES temp message key using their private key and decrypts the message with the temp key.
- Client then verifies the signature matches whats in the message using the senders public key.
- If the signarture is valid then the message is printed for the client to see.





