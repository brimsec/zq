package temporal

import (
	"context"
	"go.temporal.io/sdk/workflow"
	"testing"
	"time"

	"github.com/brimsec/zq/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/testsuite"
)

var testConfig = Config{
	SpaceCompactDelay: time.Minute,
	SpacePurgeDelay:   time.Minute,
}

func TestSpaceWorkflowWithOneWrite(t *testing.T) {
	e := (&testsuite.WorkflowTestSuite{}).NewTestWorkflowEnvironment()
	InitSpaceWorkflow(testConfig, nil, e)

	e.OnActivity(spaceCompactActivity, mock.Anything, mock.Anything).Return(nil)
	e.OnActivity(spacePurgeActivity, mock.Anything, mock.Anything).Return(nil)

	e.RegisterDelayedCallback(func() {
		e.SignalWorkflow(writeSignal, "")
	}, 0)

	e.ExecuteWorkflow(spaceWorkflow)
	require.True(t, e.IsWorkflowCompleted())
	require.True(t, workflow.IsContinueAsNewError(e.GetWorkflowError()))
	e.AssertExpectations(t)
}

func TestSpaceWorkflowWithMultipleWrites(t *testing.T) {
	e := (&testsuite.WorkflowTestSuite{}).NewTestWorkflowEnvironment()
	InitSpaceWorkflow(testConfig, nil, e)

	var compactTime time.Time
	e.OnActivity(spaceCompactActivity, mock.Anything, mock.Anything).Return(
		func(ctx context.Context, id api.SpaceID) error {
			compactTime = e.Now()
			return nil
		},
	)

	var purgeTime time.Time
	e.OnActivity(spacePurgeActivity, mock.Anything, mock.Anything).Return(
		func(ctx context.Context, id api.SpaceID) error {
			purgeTime = e.Now()
			return nil
		},
	)

	var d time.Duration
	var lastWriteTime time.Time
	for i := 0; i < 5; i++ {
		e.RegisterDelayedCallback(func() {
			lastWriteTime = e.Now()
			e.SignalWorkflow(writeSignal, "")
		}, d)
		d += config.SpaceCompactDelay - time.Second
	}

	e.ExecuteWorkflow(spaceWorkflow)
	require.True(t, e.IsWorkflowCompleted())
	require.True(t, workflow.IsContinueAsNewError(e.GetWorkflowError()))
	e.AssertExpectations(t)

	require.Equal(t, config.SpaceCompactDelay, compactTime.Sub(lastWriteTime))
	require.Equal(t, config.SpacePurgeDelay, purgeTime.Sub(compactTime))
}
