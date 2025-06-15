# mqtt-broker-flashmq
[FlashMQ](https://github.com/halfgaar/FlashMQ) fork includes plugin for auth with jwt token decode and verify.

### Purpose
To authenticate a FlashMQ connection using a custom auth plugin that verifies a username (JWT token) against an RSA PEM key passed as a base64-encoded string via the `AUTH_PUBLICKEY` environment variable

### Local Build
Its not straight-forward to compile a C/C++ FlashMQ code for a Mac processor so there is docker-compose.yml provided. To start Flashmq just type `docker-compose up --build --watch` in your favourite terminal for devlopment.
Also `devcontainer` can be attached to the running container for debugging. Line 36-38 in Docker file are updated to run the debug build for FlashMQ
![Debug Build](./images/debug-build.png) </br>
and install gdb debug servers in the container</br>
![Debug server](./images/debug-server.png)</br>
Once the container is running launch your favourite editors debug launch config


