
# add the ssh key
resource "digitalocean_ssh_key" "minitwit" {
  name = "minitwit"
  public_key = file("./ssh_key/terraform.pub")
}
