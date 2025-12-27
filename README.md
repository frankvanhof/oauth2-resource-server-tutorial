## OAuth2 Resource Server

Security Config for JWT Resource Server. A number of Rest endpoints expose specific info about a provided JWT token. There is no actual validation, just to give insight in the structure of JWT and the claims.
In src/test/resources there is a Bruno collection for calling the API. There is also a shell script that starts a Keycloak container with the data externalised. Replace podman with docker where needed. 
