package watcher

import (
	"context"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/harvester/client"
	"github.com/HewlettPackard/galadriel/pkg/harvester/spire"
)

func BuildHASelfBundleWatcher(interval time.Duration, server client.GaladrielServerClient, spire spire.SpireServer) util.RunnableTask {
	return func(ctx context.Context) error {
		t := time.NewTicker(interval)
		var currentDigest []byte

		for {
			select {
			case <-t.C:
				bundle, digest, hasNew := hasNewBundle(ctx, currentDigest, spire)
				if !hasNew {
					break
				}
				logger.Info("Bundle has changed, pushing to Galadriel Server")

				req, err := buildPostBundleRequest(bundle)
				if err != nil {
					logger.Error(err)
					break
				}

				if err = server.PostBundle(ctx, req); err != nil {
					logger.Errorf("Failed to push X.509 bundle: %v", err)
					break
				}
				logger.Debug("New bundle successfully pushed to Galadriel Server")

				currentDigest = digest
			case <-ctx.Done():
				return nil
			}
		}
	}
}
