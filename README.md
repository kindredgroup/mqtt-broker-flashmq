# mqtt-broker-flashmq
[FlashMQ](https://github.com/halfgaar/FlashMQ) fork includes plugin for auth with jwt token decode and verify.

### Purpose
To autheticate FlashMQ connection with a fit for purpose auth plugin that authenticates for username that is a jwt-token against a RSA PEM key passed as a base64 encoded string through AUTH_PUBLICKEY environment variable

### Local Build
Its not straight to compile a C/C++ FlashMQ code for Macs so provided docker-compose.yml with `docker-compose up --build --watch` is an easy local set-up inside the container for devlopment.
`devcontainer` can be attached to the running container for debugging. Line 36-38 in Docker file are updated to run the debug build for FlashMQ
![Debug Build](./images/debug-build.png) </br>
and install gdb debug servers in the container</br>
![Debug server](./images/debug-server.png)</br>
Once the container is running launch your favourite editors debug launch config


