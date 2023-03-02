package watcher

import (
	"context"
	"fmt"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/HewlettPackard/galadriel/pkg/harvester/client"
)

func BuildJWTWatcher(jwtRefreshInterval time.Duration, server client.GaladrielServerClient) util.RunnableTask {
	return func(ctx context.Context) error {
		t := time.NewTicker(jwtRefreshInterval)
		delay := jwtRefreshInterval
		for {
			select {
			case <-t.C:
				err := server.RefreshToken(ctx)
				// retries 5 times, incrementally backing-off, based on jwtRefreshInterval
				if err != nil {
					if delay >= jwtRefreshInterval+(5*10*time.Second) {
						return fmt.Errorf("failed to renew JWT token: %s", err.Error())
					}
					time.Sleep(delay)
					delay = delay + (10 * time.Second)
					break
				}
				delay = jwtRefreshInterval
			case <-ctx.Done():
				return nil
			}
		}
	}
}
