PATH=/usr/local/go/bin:$(shell echo $PATH)
HOME_DIR=~/.vault-plugins
PLUGIN_NAME=vault-plugin-secrets-pqm
PLUGIN_DIR=./vault/plugins


build:
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) cmd/vault-plugin-secrets-pqm/main.go

build-release:
	@echo "$(HOME_DIR)"
	$(shell mkdir -p $(HOME_DIR))
	go build -o $(HOME_DIR)/$(PLUGIN_NAME) cmd/vault-plugin-secrets-pqm/main.go

run-server:
	@vault server -config=./vault/server.hcl

clean:
	rm -f $(PLUGIN_DIR)/$(PLUGIN_NAME)
	pkill vault || true

dev: build
	@echo "Starting development environment..."
	@vault server -dev -config=vault/server.hcl -dev-root-token-id=root