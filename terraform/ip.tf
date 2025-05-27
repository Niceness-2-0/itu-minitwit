resource "digitalocean_floating_ip" "loadbalancer_ip" {
  region = var.region
}

resource "digitalocean_floating_ip_assignment" "assign_loadbalancer_ip" {
  ip_address = digitalocean_floating_ip.loadbalancer_ip.ip_address
  droplet_id = digitalocean_droplet.swarm_manager.id  # 🧠 match your droplet name
}

output "loadbalancer_ip" {
  value = digitalocean_floating_ip.loadbalancer_ip.ip_address
}
