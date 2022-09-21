package controller

import (
	"context"
	"github.com/HewlettPackard/galadriel/pkg/common"
)

type Client interface {
	SignalsForUpdates(ctx context.Context) chan<- *common.ControllerRequestMessage
	GetUpdatesResponse(ctx context.Context) <-chan *common.ControllerResponseMessage
}

type chanClient struct {
	controllerInChan  chan<- *common.ControllerRequestMessage
	controllerOutChan <-chan *common.ControllerResponseMessage
}

func NewChanClient(
	inChan chan<- *common.ControllerRequestMessage,
	outChan <-chan *common.ControllerResponseMessage) Client {
	return &chanClient{
		controllerInChan:  inChan,
		controllerOutChan: outChan,
	}
}

func (s *chanClient) SignalsForUpdates(ctx context.Context) chan<- *common.ControllerRequestMessage {
	return s.controllerInChan
}

func (s *chanClient) GetUpdatesResponse(ctx context.Context) <-chan *common.ControllerResponseMessage {
	return s.controllerOutChan
}
