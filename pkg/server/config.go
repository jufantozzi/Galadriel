package server

import (
	"net"

	"github.com/sirupsen/logrus"
)

// Config conveys configurations for the Galadriel Server
type Config struct {
	// Address of Galadriel Server
	TCPAddress *net.TCPAddr

	// Address of Galadriel Server to be reached locally
	LocalAddress net.Addr

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
