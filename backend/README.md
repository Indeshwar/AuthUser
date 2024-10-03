#Student Registration # Group Project

Spring boot project, get the information of the students based on their ID number.
RSA:
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in private_key.pem -out public_key.pem
