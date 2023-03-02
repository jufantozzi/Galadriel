package server

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

// Config conveys configurations for the Galadriel Server
type Config struct {
	// TCPAddress of Galadriel Server
	TCPAddress *net.TCPAddr

	// LocalAddress of Galadriel Server to be reached locally
	LocalAddress net.Addr

	// JwtTTL is the ttl to be used when signing JWTs to authenticated harvesters.
	JwtTTL time.Duration

	// Path for server's certificate. Used for harvester TLS connection.
	CertPath string

	// Path for server's certificate key. Used for harvester TLS connection
	CertKeyPath string

	// Directory to store runtime data
	DataDir string

	// DB Connection string
	DBConnString string

	Logger logrus.FieldLogger
}
