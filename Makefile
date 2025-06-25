PATH=/usr/local/go/bin:$(shell echo $PATH)
HOME_DIR=~/.vault-plugins
PLUGIN_NAME=vault-plugin-secrets-pqm
PLUGIN_DIR=./vault/plugins


build:
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) cmd/vault-plugin-secrets-pqm/main.go

build-release:
	$(shell mkdir -p $(HOME_DIR))
	go build -o $(HOME_DIR)/$(PLUGIN_NAME) cmd/vault-plugin-secrets-pqm/main.go

run-server:
	@vault server -config=./vault/server.hcl

unseal-vault:
	INIT_OUTPUT=$(shell vault operator init -key-shares=1 -key-threshold=1)
	VAULT_UNSEAL_KEY=$(shell echo "$(INIT_OUTPUT)" | grep "Unseal Key 1:" | awk '{print $NF}')
	VAULT_TOKEN=$(shell echo "$(INIT_OUTPUT)" | grep "Initial Root Token:" | awk '{print $NF}')
	$(shell vault operator unseal $(VAULT_UNSEAL_KEY))
	@echo "VAULT_TOKEN=$(VAULT_TOKEN)"

clean:
	rm -f $(PLUGIN_DIR)/$(PLUGIN_NAME)
	pkill vault || true

dev: build
	@echo "Starting development environment..."
	@vault server -dev -config=vault/server.hcl -dev-root-token-id=root