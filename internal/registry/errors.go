package registry

import "errors"

var (
	ErrUnauthenticated   = errors.New("registry principal is not authenticated")
	ErrForbidden         = errors.New("registry operation is forbidden")
	ErrNotOwner          = errors.New("registry object is owned by another principal")
	ErrExpired           = errors.New("registry object has expired")
	ErrDigestMismatch    = errors.New("registry digest does not match prepared digest")
	ErrInvalidTransition = errors.New("invalid registry state transition")
	ErrConflict          = errors.New("registry operation conflicts with existing state")
)
