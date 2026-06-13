// Package agent runs the polling loop: enroll once, then heartbeat on an
// interval, executing any commands the server hands back.
package agent

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"tiai/agent/internal/api"
	"tiai/agent/internal/collector"
	"tiai/agent/internal/config"
	"tiai/agent/internal/identity"
	"tiai/agent/internal/models"
)

// Version is the agent version reported on enroll/heartbeat.
const Version = "0.1.0"

// Agent owns the runtime state and the polling loop.
type Agent struct {
	cfg      *config.Config
	cfgPath  string
	client   *api.Client
	identity identity.Identity
}

// New creates an agent from config.
func New(cfg *config.Config, cfgPath string) *Agent {
	timeout := time.Duration(cfg.RequestTimeoutSeconds) * time.Second
	return &Agent{
		cfg:     cfg,
		cfgPath: cfgPath,
		client:  api.New(cfg.APIBaseURL, cfg.AuthToken, timeout),
	}
}

// ensureEnrolled performs trust-on-first-use enrollment if no token is stored.
func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if a.cfg.AuthToken != "" {
		return nil
	}
	fp := a.identity.Fingerprint
	resp, err := a.client.Enroll(ctx, a.cfg.EnrollmentSecret, models.EnrollRequest{
		MachineUUID:  a.identity.MachineUUID,
		AgentVersion: Version,
		Fingerprint:  &fp,
	})
	if err != nil {
		return err
	}
	a.cfg.AuthToken = resp.Token
	a.cfg.EnrollmentSecret = "" // no longer needed
	a.client.SetToken(resp.Token)
	return a.cfg.Save(a.cfgPath) // TODO: store token via DPAPI
}

// pollOnce sends a heartbeat and executes returned commands.
func (a *Agent) pollOnce(ctx context.Context) {
	state, err := collector.ReadDefenderState(ctx)
	if err != nil {
		log.Printf("collector error: %v", err)
	}
	fp := a.identity.Fingerprint
	resp, err := a.client.Heartbeat(ctx, models.HeartbeatRequest{
		AgentVersion: Version,
		Defender:     state,
		Fingerprint:  &fp,
	})
	if err != nil {
		log.Printf("heartbeat error: %v", err)
		return // TODO: local queue + back-off
	}
	for _, cmd := range resp.Commands {
		a.execute(ctx, cmd)
	}
}

func (a *Agent) execute(ctx context.Context, cmd models.Command) {
	var (
		output string
		err    error
	)
	switch cmd.Type {
	case "quick_scan":
		output, err = collector.RunQuickScan(ctx)
	case "full_scan":
		output, err = collector.RunFullScan(ctx)
	case "update_signatures":
		output, err = collector.UpdateSignatures(ctx)
	default:
		err = nil
	}

	res := models.CommandResult{Status: "succeeded", Output: output}
	if err != nil {
		res.Status = "failed"
		res.Error = err.Error()
	}
	if perr := a.client.PostResult(ctx, cmd.ID, res); perr != nil {
		log.Printf("post result error: %v", perr)
	}
}

// Run blocks, polling until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	id, err := identity.Resolve(filepath.Dir(a.cfgPath), a.cfg.MachineUUID)
	if err != nil {
		return err
	}
	a.identity = id

	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	interval := time.Duration(a.cfg.HeartbeatIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	a.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.pollOnce(ctx)
		}
	}
}
