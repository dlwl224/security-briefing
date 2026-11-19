variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "project" {
  type    = string
  default = "security-briefing"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,32}$", var.project))
    error_message = "Project must be 3-32 lowercase letters, digits or hyphens."
  }
}

variable "log_retention_days" {
  type    = number
  default = 365

  validation {
    condition     = var.log_retention_days >= 90
    error_message = "Keep audit logs for at least 90 days."
  }
}
