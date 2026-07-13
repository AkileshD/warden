# sample-agent-project

This is a sample project directory used to demonstrate Warden's ALLOW policy.

Commands targeting files inside this directory are permitted by policy rule 5:
  binary: ["*"]
  path_scope: ["./project/**"]
  action: allow
