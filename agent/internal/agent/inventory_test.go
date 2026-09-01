package agent

import (
	"strings"
	"testing"

	"tiai/agent/internal/models"
)

func TestInventoryCacheSharesTheWindowsUpdateMechanism(t *testing.T) {
	var c inventoryCache
	if state, _ := c.pending(); state != nil {
		t.Error("an agent that has not collected yet must attach no block")
	}

	c.store(&models.InventoryState{HWModel: "OptiPlex 7010"})
	state, gen := c.pending()
	if state == nil {
		t.Fatal("a fresh reading must be offered")
	}
	// Still pending until the heartbeat actually lands.
	if again, _ := c.pending(); again == nil {
		t.Error("the block must stay pending until acknowledged")
	}
	c.markSent(gen)
	if after, _ := c.pending(); after != nil {
		t.Error("an acknowledged reading must not be re-sent every 60 s")
	}
}

// The race the generation counter exists for, restated for the daily cycle: a
// collection landing between the moment a heartbeat picks up its payload and the
// moment that heartbeat succeeds must not be buried until *tomorrow*.
func TestInventoryCacheKeepsAReadingStoredMidFlight(t *testing.T) {
	var c inventoryCache
	c.store(&models.InventoryState{HWModel: "before"})
	_, gen := c.pending()

	c.store(&models.InventoryState{HWModel: "after"})
	c.markSent(gen)

	state, _ := c.pending()
	if state == nil || state.HWModel != "after" {
		t.Fatalf("the newer reading must survive the older acknowledgement, got %v", state)
	}
}

// "0 logiciel" on a poste whose collection is switched off by GPO reads as a
// failed read, when it is a policy working exactly as intended.
func TestInventoryScanSummarySaysWhenSoftwareIsOff(t *testing.T) {
	inv := &models.InventoryState{
		Disks:    []models.Disk{{DeviceID: "0"}},
		Volumes:  []models.Volume{{Letter: "C:"}, {Letter: "D:"}},
		Nics:     []models.Nic{{Key: "A"}},
		Software: nil,
	}
	off := inventoryScanSummary(inv, false)
	if !strings.Contains(off, "désactivé") {
		t.Errorf("a disabled collection must say so, got %q", off)
	}
	if strings.Contains(off, "0 logiciel") {
		t.Errorf("a disabled collection must not report a count, got %q", off)
	}

	inv.Software = []models.Software{{Name: "7-Zip"}}
	on := inventoryScanSummary(inv, true)
	if !strings.Contains(on, "1 logiciel(s)") {
		t.Errorf("an enabled collection must report its count, got %q", on)
	}
}
