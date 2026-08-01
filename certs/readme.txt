openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
chmod 644 /home/ubuntu/docker/Bookit/certs/cert.pem
chmod 644 /home/ubuntu/docker/Bookit/certs/key.pem