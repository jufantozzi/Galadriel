package endpoints

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

// Config represents the configuration of the Galadriel Server Endpoints
type Config struct {
	// TPCAddress is the address to bind the TCP listener to.
	TCPAddress *net.TCPAddr

	// LocalAddress is the local address to bind the listener to.
	LocalAddress net.Addr

	// JwtTTL is the ttl to be used when signing JWTs to authenticated harvesters.
	JwtTTL time.Duration

	// CertPath for server's certificate. Used for harvester TLS connection.
	CertPath string

	// CertKeyPath for server's certificate key. Used for harvester TLS connection
	CertKeyPath string

	// Postgres connection string
	DatastoreConnString string

	Logger logrus.FieldLogger
}
