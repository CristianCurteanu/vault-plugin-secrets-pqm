

export RELEASE="${RELEASE_TAG:-v0.0.1-rc1}"
export VERSION="${ARCHIVE_FILE:-vault-plugin-secrets-pqm_0.0.1-rc1_linux_amd64.tar.gz}"

export VAULT_PLUGINS=$HOME/.vault-plugins

mkdir -p $VAULT_PLUGINS
wget -O $VAULT_PLUGINS/vault-plugin-secrets-pqm.tar.gz https://github.com/CristianCurteanu/vault-plugin-secrets-pqm/releases/download/$RELEASE/$VERSION && tar -xzf $VAULT_PLUGINS/vault-plugin-secrets-pqm.tar.gz -C $VAULT_PLUGINS && rm -f $VAULT_PLUGINS/vault-plugin-secrets-pqm.tar.gz

export INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1)
export VAULT_UNSEAL_KEY=$(echo "$INIT_OUTPUT" | grep "Unseal Key 1:" | awk '{print $NF}')
export VAULT_TOKEN=$(echo "$INIT_OUTPUT" | grep "Initial Root Token:" | awk '{print $NF}')

echo "$VAULT_UNSEAL_KEY"
vault operator unseal $VAULT_UNSEAL_KEY

# Prepare SHA256 checksum
export SHA256=$(sha256sum $VAULT_PLUGINS/vault-plugin-secrets-pqm | cut -d' ' -f1)

# Register and enable plugin
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-pqm

# Currently this is specified for transit path, but you can use any other path as well
vault secrets enable -path=transit vault-plugin-secrets-pqm

# Check the plugin if registered
vault plugin info secret vault-plugin-secrets-pqm

echo ""
echo "Please use following command in order to make possible requests from the README:"
echo "\n\t'$ export VAULT_TOKEN=$VAULT_TOKEN'"