2016-06-02 rphall
The private key enc-key.pem is encrypted using the password 'hello'.

Commands used to generate keys:

  openssl genrsa -out key.pem 2048
  openssl rsa -in key.pem -des3 -out enc-key.pem
  openssl rsa -in key.pem -pubout -out pub-key.pem
  openssl pkcs8 -topk8 -in enc-key.pem -inform PEM -out enc-key.pkcs8 -outform PEM
  # openssl rsa -in enc-key.pem -inform PEM -pubout -out pub-key.der -outform DER
  # openssl pkcs8 -topk8 -in enc-key.pem -inform PEM -out enc-key.pkcs8.der -outform DER
  rm key.pem

