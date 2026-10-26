output "role_arn" {
  description = "Pass this to soc2kit --role-arn"
  value       = aws_iam_role.scan.arn
}
