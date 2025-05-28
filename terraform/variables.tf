variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "region" {}
variable "pub_key" {}
variable "pvt_key" {}
