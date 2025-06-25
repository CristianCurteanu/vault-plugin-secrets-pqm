plugin_directory = "/home/nerdchap/.vault-plugins"
api_addr = "http://127.0.0.1:8200"

storage "inmem" {}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = "true"
}

ui = true
disable_mlock = true