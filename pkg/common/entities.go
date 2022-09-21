package common

import (
	"github.com/google/uuid"
	"time"
)

type Operation string

const GetOperation Operation = "get"
const PushOperation Operation = "get"

type Relationship struct {
	MemberA uuid.UUID
	MemberB uuid.UUID
}

type AccessToken struct {
	Token  string
	Expiry time.Time
}

type Member struct {
	ID uuid.UUID

	Name        string
	TrustDomain string
	Tokens      []AccessToken
}

// TODO: server/harvester common packages?
type ControllerRequestMessage struct {
	Operation Operation
	Job       Job
}

type ControllerResponseMessage struct {
	Operation Operation
	Job       Job
}

type Job struct {
	MemberID uuid.UUID
	// ...
}
