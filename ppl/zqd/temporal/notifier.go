package temporal

import (
	"context"
	"time"

	"github.com/brimsec/zq/api"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.uber.org/zap"
)

type Notifier struct {
	client client.Client
	logger *zap.Logger
}

func NewNotifier(logger *zap.Logger, conf Config) (*Notifier, error) {
	client, err := NewClient(logger, conf)
	return &Notifier{client, logger}, err
}

func (n *Notifier) Shutdown() {
	n.client.Close()
}

func (n *Notifier) SpaceCreated(ctx context.Context, id api.SpaceID) {
	swo := client.StartWorkflowOptions{
		ID:        id.String(),
		TaskQueue: TaskQueue,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: time.Second,
		},
	}
	if _, err := n.client.ExecuteWorkflow(ctx, swo, spaceWorkflow); err != nil {
		n.logger.Warn("Executing workflow failed", zap.Error(err), zap.Stringer("space_id", id))
	} else {
		n.logger.Debug("Executed workflow", zap.Stringer("space_id", id))
	}
}

func (n *Notifier) SpaceDeleted(ctx context.Context, id api.SpaceID) {
	if err := n.client.CancelWorkflow(ctx, id.String(), ""); err != nil {
		n.logger.Warn("Canceling workflow failed", zap.Error(err), zap.Stringer("space_id", id))
	} else {
		n.logger.Debug("Canceled workflow", zap.Stringer("space_id", id))
	}
}

func (n *Notifier) SpaceWritten(ctx context.Context, id api.SpaceID) {
	if err := n.client.SignalWorkflow(ctx, id.String(), "", writeSignal, ""); err != nil {
		n.logger.Warn("Signaling workflow failed", zap.Error(err), zap.Stringer("space_id", id))
	} else {
		n.logger.Debug("Signaled workflow", zap.Stringer("space_id", id))
	}
}
