# Deny applies from PR comments

This is an example policies that checks if the **Plan & Apply** run was triggered in the production workspace.

To evaluate that, we have to check three attributes of the **tfrun** object:

1. **tfrun.source** - this attribute shows from which source the run was triggered. In the current example, we check if a run has source `comment-github`, for other providers, e.g. Gitlab, the source is `comment-gitlab`.
2. **input.tfrun.is_dry** - shows the type of run. If true - this is a **Plan-only** run, if false - **Plan & Apply**.
3. **input.tfrun.workspace.environment_type** - show the environment type of workspace. This attribute can have one of the following values:
   4. unmapped - type is not set
   5. development
   6. testing
   7. staging
   8. production

Also, you have to register the policy in the `scalr_policy.hcl` file. In the current example, we used `hard_mandatory` enforcement level (to hard stop the run), but also you can use `soft_mandatory` to allow users with respective permissions to approve such runs after the plan is executed.

Usually, we suggest enforcing such type of policies before the plan to catch it earlier on and not waste time waiting for the plan. Also, such type of policy failures are not reported to billing usage.
