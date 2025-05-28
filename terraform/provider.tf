# api token
# here it is exported in the environment like
# setup the provider
terraform {
        required_providers {
                digitalocean = {
                        source = "digitalocean/digitalocean"
                        version = "~> 2.37.1"
                }
                null = {
                        source = "hashicorp/null"
                        version = "3.1.0"
                }
        }
}

provider "digitalocean" {
  token = var.do_token
}