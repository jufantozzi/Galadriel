package controller

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common/telemetry"
	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/harvester/client"
	"github.com/HewlettPackard/galadriel/pkg/harvester/controller/watcher"
	"github.com/HewlettPackard/galadriel/pkg/harvester/spire"

	"github.com/sirupsen/logrus"
)

// HarvesterController represents the component responsible for handling
// the controller loops that will keep sending fresh bundles and configurations
// to and from SPIRE Server and Galadriel Server.
type HarvesterController struct {
	logger logrus.FieldLogger
	spire  spire.SpireServer
	server client.GaladrielServerClient
	config *Config
}

// Config represents the configurations for the Harvester Controller
type Config struct {
	ServerAddress         string
	RootCAPath            string
	AccessToken           string
	SpireSocketPath       net.Addr
	BundleUpdatesInterval time.Duration
	Logger                logrus.FieldLogger
}

func NewHarvesterController(ctx context.Context, gc client.GaladrielServerClient, config *Config) *HarvesterController {
	return &HarvesterController{
		spire:  spire.NewLocalSpireServer(ctx, config.SpireSocketPath),
		server: gc,
		config: config,
		logger: logrus.WithField(telemetry.SubsystemName, telemetry.HarvesterController),
	}
}

func (c *HarvesterController) Run(ctx context.Context) error {
	c.logger.Info("Starting harvester controller")

	go c.run(ctx)

	<-ctx.Done()
	c.logger.Debug("Shutting down...")

	return nil
}

func (c *HarvesterController) run(ctx context.Context) {
	federatedBundlesInterval := time.Second * 10
	jwtRefreshInterval := time.Minute * 1

	err := util.RunTasks(ctx,
		watcher.BuildSelfBundleWatcher(c.config.BundleUpdatesInterval, c.server, c.spire),
		watcher.BuildFederatedBundlesWatcher(federatedBundlesInterval, c.server, c.spire),
		watcher.BuildJWTWatcher(jwtRefreshInterval, c.server),
	)
	if err != nil && !errors.Is(err, context.Canceled) {
		c.logger.Error(err)
	}
}
