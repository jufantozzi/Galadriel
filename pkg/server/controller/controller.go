package controller

import (
	"context"
	"fmt"
	"github.com/HewlettPackard/galadriel/pkg/common"
	"github.com/HewlettPackard/galadriel/pkg/common/util"
	"github.com/google/uuid"
	"sync"
	"time"
)

type Manager interface {
	Start(ctx context.Context) error
	GetInputChan() chan<- *common.ControllerRequestMessage
	GetOutputChan() <-chan *common.ControllerRequestMessage
}

type serverManager struct {
	state             map[uuid.UUID]memberState
	controllerInChan  chan *common.ControllerRequestMessage
	controllerOutChan chan *common.ControllerResponseMessage
	mu                sync.Mutex
}

type Relationship struct {
	common.Relationship

	lastSVIDA []byte
	lastSVIDB []byte
}

type memberState struct {
	knownRelationships Relationship
}

func New() Manager {
	return &serverManager{
		controllerInChan:  make(chan *common.ControllerRequestMessage, 0),
		controllerOutChan: make(chan *common.ControllerResponseMessage, 0),
	}
}

func (s *serverManager) Start(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-ctx.Done():
			util.FromContext(ctx).Info("Gracefully stopping...")
			return nil
		case <-ticker.C:
			// check database
		case req := <-s.controllerInChan:
			// TODO: worker queue?
			fmt.Println("received req", req)
			out := &common.ControllerResponseMessage{}
			// ...
			fmt.Println("sending resp", out)
			s.controllerOutChan <- out

		}
	}
}

func (s *serverManager) GetInputChan() chan<- *common.ControllerRequestMessage {
	return s.controllerInChan
}

func (s *serverManager) GetOutputChan() <-chan *common.ControllerRequestMessage {
	return s.controllerInChan
}
