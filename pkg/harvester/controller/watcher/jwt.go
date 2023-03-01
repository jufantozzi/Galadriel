package watcher

import (
	"context"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/harvester/client"
)

// This defines how frequently we should be asking for new JWTs. The larger this number, more often it will retry.
// The actual frequency is based on the JWT TTL.
const retryFactor = 50

func BuildJWTWatcher(server client.GaladrielServerClient) util.RunnableTask {
	return func(ctx context.Context) error {
		tokenTTL := server.GetTokenTTL()
		t := time.NewTicker(tokenTTL / retryFactor)
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
