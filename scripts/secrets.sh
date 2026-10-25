mkdir -p ~/secrets

openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out ~/secrets/jwt-private.pem

openssl pkey \
  -in ~/secrets/jwt-private.pem \
  -pubout \
  -out ~/secrets/jwt-public.pem

chmod 600 ~/secrets/jwt-private.pem