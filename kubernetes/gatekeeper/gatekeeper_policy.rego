package k8s_supplychain_policy

# Enforce secure distroless base images (Wolfi or Chainguard)
# and block containers running as root.

deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  
  # Rule 1: Check image origin registry/repo. Wolfi/Chainguard are minimal.
  # Let's say we enforce Wolfi (cgr.dev/chainguard/wolfi-base) or similar distroless registry/base
  not is_approved_base(container.image)
  msg := sprintf("OPA Gatekeeper Blocked: Image '%v' does not use an approved minimal distroless base (cgr.dev/chainguard/ or wolfi)", [container.image])
}

deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  
  # Rule 2: Ensure containers do not run as root.
  is_root(container)
  msg := sprintf("OPA Gatekeeper Blocked: Container '%v' is running as root (SecurityContext.runAsNonRoot must be true)", [container.name])
}

# Helper to check if image is from approved distroless registry or contains approved keywords
is_approved_base(image) {
  contains(image, "cgr.dev/")
}
is_approved_base(image) {
  contains(image, "wolfi")
}
is_approved_base(image) {
  # For internal trusted registries that inherit secure bases
  contains(image, "harbor.internal.fintech/finance/")
}

# Helper to check if running as root
is_root(container) {
  container.securityContext.runAsRoot == true
}
is_root(container) {
  not container.securityContext.runAsNonRoot == true
}
