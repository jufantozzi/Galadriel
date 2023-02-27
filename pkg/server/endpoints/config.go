package endpoints

import (
	"net"

	"github.com/sirupsen/logrus"
)

// Config represents the configuration of the Galadriel Server Endpoints
type Config struct {
	// TPCAddr is the address to bind the TCP listener to.
	TCPAddress *net.TCPAddr

	// LocalAddress is the local address to bind the listener to.
	LocalAddress net.Addr

	// Path for server's certificate. Used for harvester TLS connection.
	CertPath string

	// Path for server's certificate key. Used for harvester TLS connection
	CertKeyPath string

	// Postgres connection string
	DatastoreConnString string

	Logger logrus.FieldLogger
}
