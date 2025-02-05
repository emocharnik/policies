package terraform

# Return denial message if the apply should be blocked
deny[{"msg": "Applying from PR comments is not allowed in production workspaces."}] {
  input.tfrun.source == "comment-github"
  input.tfrun.is_dry == false
  input.tfrun.workspace.environment_type == "production"
}
