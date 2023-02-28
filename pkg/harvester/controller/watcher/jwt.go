package watcher

import (
	"context"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/harvester/client"
)

const bundleRefreshInterval = time.Second * 10

func BuildJWTWatcher(server client.GaladrielServerClient) util.RunnableTask {
	return func(ctx context.Context) error {
		t := time.NewTicker(bundleRefreshInterval)
		for {
			select {
			case <-t.C:
				err := server.RefreshToken(ctx)
				if err != nil {
					logger.Errorf("Failed to refresh JWT: %v", err)
					break
				}
			case <-ctx.Done():
				return nil
			}
		}
	}
}
