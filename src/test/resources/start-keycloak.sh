# sudo mkdir -m 777 ./keycloak_data
podman run -p 8080:8080 -v ./keycloak_data:/opt/keycloak/data/h2 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.4.7 start-dev
