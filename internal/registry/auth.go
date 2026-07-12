package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

type Scope string

const (
	ScopeObservationPrepare Scope = "observation:prepare"
	ScopeObservationCommit  Scope = "observation:commit"
	ScopeOwnershipManage    Scope = "ownership:manage"
	ScopeDisputeCreate      Scope = "dispute:create"
	ScopeRunnerSubmit       Scope = "runner:submit"
	ScopeModerationReview   Scope = "moderation:review"
	ScopeRegistryAdmin      Scope = "registry:admin"
)

var validScopes = map[Scope]struct{}{
	ScopeObservationPrepare: {},
	ScopeObservationCommit:  {},
	ScopeOwnershipManage:    {},
	ScopeDisputeCreate:      {},
	ScopeRunnerSubmit:       {},
	ScopeModerationReview:   {},
	ScopeRegistryAdmin:      {},
}

type PrincipalID string

func (id PrincipalID) Validate() error {
	value := string(id)
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return errors.New("principal ID must be 1..512 non-whitespace bytes")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("principal ID contains a control character")
		}
	}
	return nil
}

// Principal is an authenticated issuer/subject identity with an exact set of
// Registry scopes.  It deliberately has no implicit admin bypass.
type Principal struct {
	id     PrincipalID
	scopes map[Scope]struct{}
}

func NewPrincipal(id PrincipalID, scopes ...Scope) (Principal, error) {
	if err := id.Validate(); err != nil {
		return Principal{}, err
	}
	principal := Principal{id: id, scopes: make(map[Scope]struct{}, len(scopes))}
	for _, scope := range scopes {
		if _, valid := validScopes[scope]; !valid {
			return Principal{}, fmt.Errorf("unknown Registry scope %q", scope)
		}
		if _, duplicate := principal.scopes[scope]; duplicate {
			return Principal{}, fmt.Errorf("duplicate Registry scope %q", scope)
		}
		principal.scopes[scope] = struct{}{}
	}
	return principal, nil
}

func (principal Principal) ID() PrincipalID { return principal.id }

func (principal Principal) Scopes() []Scope {
	result := make([]Scope, 0, len(principal.scopes))
	for scope := range principal.scopes {
		result = append(result, scope)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (principal Principal) HasScope(scope Scope) bool {
	_, ok := principal.scopes[scope]
	return ok
}

func (principal Principal) RequireScope(scope Scope) error {
	if err := principal.id.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if _, valid := validScopes[scope]; !valid {
		return fmt.Errorf("%w: unknown required scope %q", ErrForbidden, scope)
	}
	if !principal.HasScope(scope) {
		return fmt.Errorf("%w: scope %s is required", ErrForbidden, scope)
	}
	return nil
}

func authorizeOwned(principal Principal, owner PrincipalID, scope Scope) error {
	// Check the capability before revealing whether an object exists or who
	// owns it, which avoids turning an endpoint into an ownership oracle.
	if err := principal.RequireScope(scope); err != nil {
		return err
	}
	if principal.ID() != owner {
		return ErrNotOwner
	}
	return nil
}
