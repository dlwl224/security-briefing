variable "name" {
  description = "Bucket name"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.name))
    error_message = "Bucket name must be 3-63 lowercase letters, digits or hyphens."
  }
}

variable "policy_json" {
  description = "Extra bucket policy statements merged with the TLS-only rule"
  type        = string
  default     = null
}

variable "expiration_days" {
  description = "Delete current objects after this many days (null keeps them)"
  type        = number
  default     = null
}

variable "noncurrent_version_days" {
  description = "Delete previous object versions after this many days"
  type        = number
  default     = 90
}
