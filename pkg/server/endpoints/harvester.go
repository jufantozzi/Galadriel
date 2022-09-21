package endpoints

import (
	"context"
	"github.com/HewlettPackard/galadriel/pkg/common"
	"github.com/google/uuid"
	"net/http"
)

func (e *EndpointHandler) getUpdatesHandler(ctx context.Context) {
	http.HandleFunc("/getUpdates", func(w http.ResponseWriter, r *http.Request) {
		// TODO: auth
		memberID, err := uuid.Parse(r.Header.Get("memberID"))
		if err != nil {
			e.Log.Errorf("failed parsing uuid: %v", err)
			w.WriteHeader(400)
			return
		}
		updateReq := &common.ControllerRequestMessage{
			Operation: common.GetOperation,
			Job:       common.Job{MemberID: memberID},
		}
		jobs := e.ControllerHandler.SignalsForUpdates(memberID)

		_, err = w.Write([]byte("ok"))
		if err != nil {
			return
		}
	})
}
