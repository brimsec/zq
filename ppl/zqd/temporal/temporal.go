package temporal

import (
	"flag"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/server/common/log"
	"go.uber.org/zap"
)

const TaskQueue = "zqd"

type Config struct {
	Addr      string
	Enabled   bool
	Namespace string
	// SpaceCompactDelay is the delay between the last write operation and a
	// compact operation.  A write during this delay resets the timer.
	SpaceCompactDelay time.Duration
	// SpacePurgeDelay is the delay between a compact operation and a purge
	// operation.
	SpacePurgeDelay time.Duration
}

func (c *Config) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Addr, "temporal.addr", "", "Temporal frontend service address")
	fs.BoolVar(&c.Enabled, "temporal.enabled", false, "enable Temporal")
	fs.StringVar(&c.Namespace, "temporal.namespace", "", "Temporal namespace")
	fs.DurationVar(&c.SpaceCompactDelay, "temporal.spacecompactdelay", time.Minute, "delay between last write and compact")
	fs.DurationVar(&c.SpacePurgeDelay, "temporal.spacepurgedelay", time.Minute, "delay between compact and purge")
}

func NewClient(logger *zap.Logger, conf Config) (client.Client, error) {
	return client.NewClient(client.Options{
		HostPort:  conf.Addr,
		Namespace: conf.Namespace,
		Logger:    log.NewZapAdapter(logger),
	})
}
