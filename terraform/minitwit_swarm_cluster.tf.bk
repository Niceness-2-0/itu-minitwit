resource "digitalocean_droplet" "manager" {
  name       = "manager"
  region     = var.region
  size       = var.size
  image      = "ubuntu-20-04-x64"
  ssh_keys   = [digitalocean_ssh_key.minitwit.id]
  tags       = ["swarm", "manager"]
}

resource "digitalocean_droplet" "worker" {
  count      = 2
  name       = "worker-${count.index}"
  region     = var.region
  size       = var.size
  image      = "ubuntu-20-04-x64"
  ssh_keys   = [digitalocean_ssh_key.minitwit.id]
  tags       = ["swarm", "worker"]
}
