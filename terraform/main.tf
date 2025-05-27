resource "digitalocean_droplet" "swarm_manager" {
  name   = "swarm-manager"
  region = var.region
  size   = var.droplet_size
  image  = "docker-20-04" # or ubuntu + cloud-init

  ssh_keys = [var.ssh_fingerprint]
  tags     = ["swarm", "manager"]

  connection {
    type        = "ssh"
    user        = "root"
    private_key = file(var.private_key_path)
    host        = self.ipv4_address
  }

  provisioner "file" {
    source      = "scripts/"
    destination = "/opt/myapp"
  }

  provisioner "remote-exec" {
    inline = [
      "docker swarm init",
      "chmod +x /opt/myapp/deploy.sh",
      "/opt/myapp/deploy.sh"
    ]
  }
}
