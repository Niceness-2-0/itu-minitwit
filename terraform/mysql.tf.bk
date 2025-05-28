resource "digitalocean_database_cluster" "mysql" {
  name       = "minitwit-db"
  engine     = "mysql"
  version    = "8"
  size       = "db-s-1vcpu-1gb"
  region     = var.region
  node_count = 1
}

output "mysql_host" {
  value = digitalocean_database_cluster.mysql.host
}

output "mysql_port" {
  value = digitalocean_database_cluster.mysql.port
}

output "mysql_user" {
  value = digitalocean_database_cluster.mysql.user
}

output "mysql_password" {
  value     = digitalocean_database_cluster.mysql.password
  sensitive = true
}

output "mysql_db_name" {
  value = digitalocean_database_cluster.mysql.db_names[0]
}
