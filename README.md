# vault-plugin-secrets-pqm

This secrets engine enables encryption and decryption using post-quantum algorithms, like kyber.


## Prerequisites

1. Golang 1.18+
2. Vault CLI intalled

## Install

Follow the steps below in order to install this plugin in a running Vault server

### 1. Get the plugin binary

There are two possible ways to do that. 

First you can download it from this repo's release page, and you can use following commands:

```sh
export RELEASE=v0.0.1-rc1
export VERSION=vault-plugin-secrets-pqm_0.0.1-rc1_linux_amd64.tar.gz
export VAULT_PLUGINS=~/.vault-plugins
wget -O $VAULT_PLUGINS/vault-plugin-secrets-pqm.tar.gz https://github.com/CristianCurteanu/vault-plugin-secrets-pqm/releases/download/$RELEASE/$VERSION && tar -xzf $VAULT_PLUGINS/vault-plugin-secrets-pqm.tar.gz -C $VAULT_PLUGINS && rm -f $VAULT_PLUGINS/vault-plugin-secrets-pqm.tar.gz
```

Please make sure to use proper values, for the release and version that you want to use from [release page](https://github.com/CristianCurteanu/vault-plugin-secrets-pqm/releases).

Otherwise, you can build it from source, by cloning this repo on your instance, and running following build command:

```sh
make build-release
```

### 2. Launch the vault server

You can either run this local server, with configurations from `.vault/server.hcl` configuration using this command:

```sh
make run-server
```

or you can run using your own server configuration file:

```sh
vault server -config=/path/to/server/config.hcl
```

Keep in mind to specify the absolute path to your `$GOPATH/bin` directory in your server.hcl (`plugin_directory`, property)

### 3. Register and enable plugin

There are two steps to needs to be taken in order to register the plugin. First, we will need to unseal the Vault, and you can do that using following commands:

```sh
# First, we will need an operator to be initialized
# It's good to store the output, so that tokens could be used later on
export INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1)
export VAULT_UNSEAL_KEY=$(echo "$INIT_OUTPUT" | grep "Unseal Key 1:" | awk '{print $NF}')
export VAULT_TOKEN=$(echo "$INIT_OUTPUT" | grep "Initial Root Token:" | awk '{print $NF}')

# And now, the unseal command
vault operator unseal $VAULT_UNSEAL_KEY
```

Now that we unsealed the Vault, we need to register and enable the plugin:

```sh
# Prepare SHA256 checksum
export SHA256=$(sha256sum $GOPATH/bin/vault-plugin-secrets-pqm | cut -d' ' -f1)

# Register and enable plugin
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-pqm

# Currently this is specified for transit path, but you can use any other path as well
vault secrets enable -path=transit vault-plugin-secrets-pqm

# Check the plugin if registered
vault plugin info secret vault-plugin-secrets-pqm
```

### Installation script

You can also use the installation script from `script` directory, by running this command:

```sh
sh scripts/install.sh
```

Or, with specified tag, or release archive file:

```sh
RELEASE_TAG=<release-version> ARCHIVE_FILE=<release-archive-file> sh scripts/install.sh
```

But, please make sure to run the server first, as this script does not do it.

It's been tested on Ubuntu linux, but contact me if you have any issues running that script.

## Usage

There is possibility to use this plugin using HTTP API, using cURL (or any other HTTP requests tool)

### Using cURL

1. Create a new key

```sh
curl -X POST \  
   "X-Vault-Token: $VAULT_TOKEN" \  
   -d '{"type": "kyber-512"}' \ 
   http://localhost:8200/v1/transit/keys/new-kyber-key
```

2. Encrypt the value

```sh
curl -X POST \ 
   "X-Vault-Token: $VAULT_TOKEN" \  
   -d '{"type": "kyber-512", "key_version":1, "plaintext": "Hello, Vault!"}' \  
   http://localhost:8200/v1/transit/encrypt/new-kyber-key
```

3. Decrypt the key

```sh
curl -X POST \  
   "X-Vault-Token: $VAULT_TOKEN" \ 
   -d '{"type": "kyber-512", "key_version":1, "ciphertext": "vault:v1:<encrypted-value>"}' \ 
  http://localhost:8200/v1/transit/decrypt/new-kyber-key
```

Please note that the `$VAULT_TOKEN` value is provided when Vault is unsealed, so please make sure to store that value.

Also, keep in mind to seal the Vault after all the encryption/decryption operations are complete, by running this command:

```sh
vault operator seal
```

When you will shutdown the server it will seal automatically, but this operation should be done if the Vault server continues to run.

## Development

### Add new algorithms

In order to add new algorithm, you need to create a struct that implements `encryptor` interface:

```go
type encryptor interface {
	GetName() string
	GetKeyGen() ([]byte, error)
	GetAlgorithms() algorithms
}
```

This way, you new algorithm, good look like this:

```go
type newAlgorithm struct {
   // Define all the required fields
}

func (k *newAlgorithm) GetName() string {
	return "algorithm-name"
}

func (k *newAlgorithm) GetKeyGen() ([]byte, error) {
	return getKeyGen() // Or any other kind of logic
}

func (k *newAlgorithm) GetAlgorithms() algorithms {
	return algorithms{
		encrypt: func(key, data []byte) ([]byte, error) { return nil, nil },
		decrypt: func(key, data []byte) ([]byte, error) { return nil, nil },
	}
}
```

Of course this is a placeholder struct, but this will give an idea how it should be done.

After which, there is a algorithms registry in `PqBackend` struct, and a new instance of `newAlgorithm` could be added to the `newContainer().Register(algorithms...)` line; and after rebuild and re-enable it in the Vault plugins registry, it will be available.

## TODOs

- [ ] Create Docker image for it
- [ ] Add Dilithium encryption/decryption algorithms
- [ ] Add all the command lines from usage section to the `Makefile`
- [ ] Add documentation for Vault CLI usage

## Additional references:

- [Upgrading Plugins](https://www.vaultproject.io/docs/upgrading/plugins)
- [List of Vault Plugins](https://www.vaultproject.io/docs/plugin-portal)
