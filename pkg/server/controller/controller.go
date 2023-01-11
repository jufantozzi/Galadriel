package controller

import "github.com/google/uuid"

// Controller ...
type Controller interface {
	Request(memberID uuid.UUID) bool
}

type Locker struct {
}

func (l *Locker) Request(memberID uuid.UUID) bool { return false }

func NewServerController() (Controller, error) {
	return &Locker{}, nil
}
