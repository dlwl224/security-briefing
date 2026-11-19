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

variable "github_repo" {
  description = "owner/name allowed to assume the CI roles"
  type        = string
  default     = "dlwl224/security-briefing"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repo))
    error_message = "github_repo must look like owner/name."
  }
}

variable "apply_environment" {
  description = "GitHub environment that gates terraform apply"
  type        = string
  default     = "aws"
}
