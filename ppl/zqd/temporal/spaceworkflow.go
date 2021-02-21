package temporal

import (
	"context"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/brimsec/zq/ppl/zqd/apiserver"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

var config Config
var manager *apiserver.Manager

func InitSpaceWorkflow(c Config, m *apiserver.Manager, r worker.Registry) {
	config = c
	manager = m
	r.RegisterWorkflow(spaceWorkflow)
	r.RegisterActivity(spaceCompactActivity)
	r.RegisterActivity(spacePurgeActivity)
}

const writeSignal = "write"

func spaceWorkflow(ctx workflow.Context) error {
	logger := workflow.GetLogger(ctx)
	logger.Info("Workflow started")
	signalCh := workflow.GetSignalChannel(ctx, writeSignal)
	for {
		logger.Info("Workflow waiting for signal")
		var signalVal string
		signalCh.Receive(ctx, &signalVal)

		logger.Info("Workflow waiting for timer or signal")
		s := workflow.NewSelector(ctx)
		timerCtx, cancel := workflow.WithCancel(ctx)
		timerFuture := workflow.NewTimer(timerCtx, config.SpaceCompactDelay)
		var err error
		var executedActivity bool
		s.AddFuture(timerFuture, func(_ workflow.Future) {
			logger.Info("Workflow timer expired")
			ctx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
				StartToCloseTimeout: 12 * time.Hour,
			})
			id := api.SpaceID(workflow.GetInfo(ctx).WorkflowExecution.ID)
			err = workflow.ExecuteActivity(ctx, spaceCompactActivity, id).Get(ctx, nil)
			if err == nil {
				err = workflow.Sleep(ctx, config.SpacePurgeDelay)
			}
			if err == nil {
				err = workflow.ExecuteActivity(ctx, spacePurgeActivity, id).Get(ctx, nil)
			}
			executedActivity = true
		})
		s.AddReceive(signalCh, func(c workflow.ReceiveChannel, more bool) {
			logger.Info("Workflow signal arrived")
		})
		s.Select(ctx)
		cancel()

		if executedActivity {
			if err != nil {
				logger.Error("Workflow failed", "error", err)
				return err
			}

			// If there are no pending signals, continue as new.
			s = workflow.NewSelector(ctx)
			s.AddReceive(signalCh, func(c workflow.ReceiveChannel, more bool) {})
			if !s.HasPending() {
				return workflow.NewContinueAsNewError(ctx, spaceWorkflow)
			}
		}
	}
}

func spaceCompactActivity(ctx context.Context, id api.SpaceID) error {
	l := activity.GetLogger(ctx)
	l.Info("Activity started")
	if err := manager.Compact(ctx, id); err != nil {
		l.Error("Activity failed", "error", err)
		return err
	}
	l.Info("Activity completed")
	return nil
}

func spacePurgeActivity(ctx context.Context, id api.SpaceID) error {
	l := activity.GetLogger(ctx)
	l.Info("Activity started")
	if err := manager.Purge(ctx, id); err != nil {
		l.Error("Activity failed", "error", err)
		return err
	}
	l.Info("Activity completed")
	return nil
}
