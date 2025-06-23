.PHONY: build test clean

PLUGIN_NAME=vault-plugin-secrets-pqm
PLUGIN_DIR=./vault/plugins

build:
	@go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) main.go

test:
	@echo "Starting Vault server..."
	@vault server -config=vault/server.hcl -dev-root-token-id=root &
	@sleep 3
	@echo "Registering plugin..."
	@export VAULT_ADDR=http://127.0.0.1:8200 && \
	 export VAULT_TOKEN=root && \
	 SHA256=$$(sha256sum $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d' ' -f1) && \
	 vault plugin register -sha256=$$SHA256 -command=$(PLUGIN_NAME) secret transit
	@echo "Enabling plugin..."
	@export VAULT_ADDR=http://127.0.0.1:8200 && \
	 export VAULT_TOKEN=root && \
	 vault secrets enable plugin

clean:
	rm -f $(PLUGIN_DIR)/$(PLUGIN_NAME)
	pkill vault || true

dev: build
	@echo "Starting development environment..."
	@vault server -config=vault/server.hcl -dev-root-token-id=root