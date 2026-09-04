package engine

import "fmt"

// errSeedOutOfScope reports a seed URL that falls outside the declared scope.
func errSeedOutOfScope(seed string) error {
	return fmt.Errorf("seed %q is not inside the configured in_scope patterns; "+
		"add its host to scope.in_scope or remove the seed", seed)
}
