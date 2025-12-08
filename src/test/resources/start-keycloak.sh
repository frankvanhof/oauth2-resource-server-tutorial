#!/bin/bash

KEYCLOAK_DEV_DATA_DIR=./keycloak_data
if ! test -d "$KEYCLOAK_DEV_DATA_DIR"; then
    sudo mkdir -m 777 "$KEYCLOAK_DEV_DATA_DIR"
fi

podman run \
  --publish 8080:8080 \
  --volume "$KEYCLOAK_DEV_DATA_DIR":/opt/keycloak/data/h2 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.4.7 \
  start-dev