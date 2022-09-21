package server

import (
	"context"
	"errors"
	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/server/catalog"
	"github.com/HewlettPackard/galadriel/pkg/server/controller"
	"github.com/HewlettPackard/galadriel/pkg/server/endpoints"
	"github.com/sirupsen/logrus"
)

// Server represents a Galadriel Server.
type Server struct {
	config  *Config
	manager controller.Manager
}

// New creates a new instance of the Galadriel Server.
func New(config *Config) *Server {
	return &Server{config: config}
}

// Run starts running the Galadriel Server, starting its endpoints and its manager.
func (s *Server) Run(ctx context.Context) error {
	if err := s.run(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Server) run(ctx context.Context) (err error) {
	s.manager = controller.New()

	cat, err := catalog.Load(ctx, catalog.Config{Log: s.config.Log})
	if err != nil {
		return err
	}
	defer cat.Close()

	endpointsServer, err := s.newEndpointsServer(ctx, cat)
	if err != nil {
		return err
	}

	tasks := []func(context.Context) error{
		endpointsServer.ListenAndServe,
		s.manager.Start,
	}

	err = util.RunTasks(ctx, tasks)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (s *Server) newEndpointsServer(ctx context.Context, cat catalog.Catalog) (endpoints.Server, error) {
	config := endpoints.Config{
		TCPAddress:   s.config.TCPAddress,
		LocalAddress: s.config.LocalAddress,
		Catalog:      cat,
		// TODO: logger package
		Log: util.FromContext(ctx).WithFields(logrus.Fields{
			"TCPAddress":   s.config.TCPAddress,
			"LocalAddress": s.config.LocalAddress,
		}),
	}

	return endpoints.New(config)
}
