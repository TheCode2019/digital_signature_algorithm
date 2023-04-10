# digital_singature_algorithm

Just a simple C algorithm that generates an RSA key pair, signs a message using the private key and verifies the signature using the public key. The signature is calculated by hashing the message using SHA256 and then signing the hash with the private key. The verification process is made by hashing the message again, and then verifying the signature with the public key.
