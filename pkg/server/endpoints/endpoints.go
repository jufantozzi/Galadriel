package endpoints

import (
	"context"
	"fmt"
	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/server/controller"
	"github.com/HewlettPackard/galadriel/pkg/server/datastore"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
)

// Server manages the UDS and TCP endpoints lifecycle
type Server interface {
	// ListenAndServe starts all endpoint servers and blocks until the context
	// is canceled or any of the endpoints fails to run.
	ListenAndServe(ctx context.Context) error
}

type EndpointHandler struct {
	TCPAddress       *net.TCPAddr
	LocalAddr        net.Addr
	DataStore        datastore.DataStore
	ControllerClient controller.Client
	Log              logrus.FieldLogger
}

func New(c Config) (*EndpointHandler, error) {
	if err := util.PrepareLocalAddr(c.LocalAddress); err != nil {
		return nil, err
	}
	return &EndpointHandler{
		TCPAddress: c.TCPAddress,
		LocalAddr:  c.LocalAddress,
		DataStore:  c.Catalog.GetDataStore(),
		Log:        c.Log,
	}, nil
}

func (e *EndpointHandler) ListenAndServe(ctx context.Context) error {
	l, err := net.Listen(e.LocalAddr.Network(), e.LocalAddr.String())
	if err != nil {
		return fmt.Errorf("error listening on uds: %w", err)
	}
	defer l.Close()

	e.addHandlers(ctx)

	localServer := &http.Server{}
	tcpServer := echo.New()

	errLocalServer := make(chan error)
	go func() {
		errLocalServer <- localServer.Serve(l)
	}()

	errTcpServer := make(chan error)
	go func() {
		errTcpServer <- tcpServer.Start(e.TCPAddress.String())
	}()

	select {
	case err = <-errLocalServer:
	case <-ctx.Done():
		if err != nil {
			fmt.Printf("error serving HTTP on uds: %v", err)
		}
		e.Log.Println("Stopping HTTP Server")
		localServer.Close()
		tcpServer.Close()
	}

	return nil
}

func (e *EndpointHandler) addHandlers(ctx context.Context) {
	e.createMemberHandler(ctx)
	e.createRelationshipHandler(ctx)
	e.generateTokenHandler(ctx)
}
