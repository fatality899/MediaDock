#!/usr/bin/env bash
# Service: gluetun — Client VPN avec kill-switch
# API Port: 8888

export GLUETUN_PORT=8888
export GLUETUN_API_PATH="/v1"

gluetun_get_api_key() {
  :  # TODO: Story future — Gluetun n'a pas d'API key
}

gluetun_wait_ready() {
  :  # TODO: Story future
}

gluetun_configure() {
  :  # TODO: Story future
}
