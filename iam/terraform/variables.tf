variable "region" {
  description = "Region for the provider (IAM is global)."
  type        = string
  default     = "us-east-1"
}

variable "trusted_principal_arn" {
  description = "ARN of the principal allowed to assume the scan role (e.g. arn:aws:iam::111122223333:role/auditor)."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:(root|role/.+|user/.+)$", var.trusted_principal_arn))
    error_message = "Must be an IAM account root, role or user ARN."
  }
}

variable "external_id" {
  description = "Shared secret the scanner must present when assuming the role (16-128 chars)."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.external_id) >= 16 && length(var.external_id) <= 128
    error_message = "external_id must be 16-128 characters."
  }
}

variable "role_name" {
  description = "Name of the IAM role to create."
  type        = string
  default     = "soc2kit-readonly"
}
