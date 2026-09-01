package collector

import (
	"net"
	"testing"
)

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	hw, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("bad test MAC %q: %v", s, err)
	}
	return hw
}

func TestNicType(t *testing.T) {
	if got := nicType(ifTypeEthernet); got != "ethernet" {
		t.Errorf("got %q", got)
	}
	if got := nicType(ifTypeWiFi); got != "wifi" {
		t.Errorf("got %q", got)
	}
	// A PPP link, a Bluetooth PAN, a tunnel: shown without distinguishing.
	if got := nicType(23); got != "other" {
		t.Errorf("got %q", got)
	}
}

// Windows reports the maximum of a uint64 for an adapter that is not connected.
// Eighteen exabits per second is not a link speed.
func TestLinkSpeedMbps(t *testing.T) {
	if got := linkSpeedMbps(1_000_000_000); got == nil || *got != 1000 {
		t.Errorf("a gigabit link must read 1000, got %v", got)
	}
	if got := linkSpeedMbps(unknownLinkSpeed); got != nil {
		t.Errorf("a disconnected adapter must report no speed, got %v", got)
	}
	if got := linkSpeedMbps(0); got != nil {
		t.Errorf("zero must report no speed, got %v", got)
	}
	// A sub-megabit link rounds up rather than reading as "no link".
	if got := linkSpeedMbps(500_000); got == nil || *got != 1 {
		t.Errorf("a sub-megabit link must round up, got %v", got)
	}
}

func TestBuildNicsKeysOnTheMacThenTheName(t *testing.T) {
	got := buildNics([]rawAdapter{
		{Name: "Intel(R) Ethernet I219-LM", MAC: mac(t, "aa:bb:cc:dd:ee:ff"),
			IfType: ifTypeEthernet, SpeedBits: 1_000_000_000, Up: true, DHCP: true,
			Addresses:  []net.IP{net.ParseIP("10.4.1.20")},
			PrefixLens: []uint8{16}, Gateway: "10.4.0.1"},
		// A PPP or tunnel pseudo-adapter: no hardware address, and a row still
		// needs a key the server can upsert on.
		{Name: "WAN Miniport (PPP)", IfType: 23},
		// Neither a MAC nor a name: nothing to key on at all.
		{IfType: 23},
	}, map[string]bool{"AA:BB:CC:DD:EE:FF": true})

	if len(got) != 2 {
		t.Fatalf("expected 2 adapters, got %d", len(got))
	}
	if got[0].Key != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("the MAC is the key when there is one, got %q", got[0].Key)
	}
	if got[0].IPPrefixLength != 16 {
		t.Errorf("prefix %d", got[0].IPPrefixLength)
	}
	if got[0].IsVirtual {
		t.Error("an adapter Windows calls physical must not read as virtual")
	}
	if got[0].IsDHCP == nil || !*got[0].IsDHCP {
		t.Error("the DHCP flag must be reported")
	}
	if got[1].Key != "WAN Miniport (PPP)" {
		t.Errorf("the name is the fallback key, got %q", got[1].Key)
	}
}

// The bit comes from Win32_NetworkAdapter, which is the only place Windows says
// whether an adapter is a real card — matching descriptions against a list of
// hypervisor product names is the heuristic the address election already
// refused.
func TestBuildNicsFlagsVirtualAdapters(t *testing.T) {
	adapters := []rawAdapter{
		{Name: "Hyper-V Virtual Ethernet Adapter", MAC: mac(t, "00:15:5d:01:02:03")},
	}
	got := buildNics(adapters, map[string]bool{"00:15:5D:01:02:03": false})
	if !got[0].IsVirtual {
		t.Error("an adapter Windows calls non-physical must read as virtual")
	}

	// An empty map is the failure case, and it errs towards physical: showing a
	// Hyper-V switch as a real card is cosmetic, hiding a real card is not.
	got = buildNics(adapters, nil)
	if got[0].IsVirtual {
		t.Error("with no evidence, an adapter must not be called virtual")
	}
}

// One address per adapter, and the one an administrator would use: a list of six
// link-local IPv6 addresses answers nothing.
func TestPreferredAddressPrefersIPv4AndSkipsTheUnusable(t *testing.T) {
	a := rawAdapter{
		Addresses: []net.IP{
			net.ParseIP("169.254.10.1"), // APIPA: a failed DHCP lease
			net.ParseIP("fe80::1"),      // link-local
			net.ParseIP("2001:db8::1"),
			net.ParseIP("10.4.1.20"),
		},
		PrefixLens: []uint8{16, 64, 64, 24},
	}
	ip, prefix := preferredAddress(a)
	if ip == nil || ip.String() != "10.4.1.20" || prefix != 24 {
		t.Errorf("got %v/%d, want 10.4.1.20/24", ip, prefix)
	}

	// An adapter with no IPv4 falls back to its routable IPv6.
	a.Addresses = []net.IP{net.ParseIP("fe80::1"), net.ParseIP("2001:db8::1")}
	a.PrefixLens = []uint8{64, 64}
	ip, _ = preferredAddress(a)
	if ip == nil || ip.String() != "2001:db8::1" {
		t.Errorf("got %v, want the routable IPv6", ip)
	}

	// A disconnected adapter has nothing to show, and that is not an error.
	if ip, _ := preferredAddress(rawAdapter{}); ip != nil {
		t.Errorf("got %v, want nothing", ip)
	}
}
