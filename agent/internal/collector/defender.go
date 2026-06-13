// Package collector reads Microsoft Defender state.
//
// Target implementation (M2): query WMI namespace ROOT\Microsoft\Windows\Defender
// (class MSFT_MpComputerStatus) via github.com/yusufpapurcu/wmi, and run scans /
// signature updates through MSFT_MpScan.Start / MSFT_MpSignature.Update.
//
// The existing agent in natimai-windows-console already implements this; port
// internal/collector/defender.go from there. This stub keeps the skeleton
// buildable on any platform.
package collector

import (
	"context"

	"tiai/agent/internal/models"
)

// ReadDefenderState returns the current Defender status.
func ReadDefenderState(ctx context.Context) (*models.DefenderState, error) {
	// TODO(M2): WMI MSFT_MpComputerStatus.
	return &models.DefenderState{}, nil
}

// RunQuickScan triggers a Defender quick scan.
func RunQuickScan(ctx context.Context) (string, error) {
	// TODO(M2): MSFT_MpScan.Start(ScanType=Quick).
	return "", nil
}

// RunFullScan triggers a Defender full scan.
func RunFullScan(ctx context.Context) (string, error) {
	// TODO(M2): MSFT_MpScan.Start(ScanType=Full).
	return "", nil
}

// UpdateSignatures triggers a Defender signature update.
func UpdateSignatures(ctx context.Context) (string, error) {
	// TODO(M2): MSFT_MpSignature.Update().
	return "", nil
}
