package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gaaFlags: gateways are the one extra we ask for — they are what tells a real
// NIC from a host-only virtual switch (see betterAddress). Everything we don't
// read is skipped, which is both cheaper and a smaller buffer to size. The
// physical address needs no flag: it is a field of the adapter structure
// itself, always filled in.
const gaaFlags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
	windows.GAA_FLAG_SKIP_ANYCAST |
	windows.GAA_FLAG_SKIP_MULTICAST |
	windows.GAA_FLAG_SKIP_DNS_SERVER |
	windows.GAA_FLAG_SKIP_FRIENDLY_NAME

const (
	// initialAdapterBufSize is the 15 KB starting size MSDN recommends for
	// GetAdaptersAddresses: sizing with a first, bufferless call costs a second
	// enumeration and still races the adapter list, so we start big instead.
	initialAdapterBufSize = 15 * 1024
	// adapterBufAttempts bounds the grow-and-retry loop. Two would do in
	// practice; the extra rounds cover an adapter appearing between two calls.
	adapterBufAttempts = 4
)

// ReadNetwork returns the machine's primary IP address, the MAC of the adapter
// holding it and the mask that address sits behind. All are empty when nothing
// qualifies (see usableAddress).
//
// Read on every heartbeat rather than cached at start-up like sysinfo: a DHCP
// renewal, a docking station or a VPN changes the address while the agent keeps
// running, and an address that is a week stale is worse than none. The MAC
// changes far less often, but it is elected *with* the address rather than
// separately — a MAC read off another adapter than the reported one is what
// would make a Wake-on-LAN packet land on the wrong subnet.
func ReadNetwork(ctx context.Context) (NetworkInfo, error) {
	if err := ctx.Err(); err != nil {
		return NetworkInfo{}, err
	}
	addrs, err := enumerateAddresses()
	if err != nil {
		return NetworkInfo{}, err
	}
	return elect(addrs), nil
}

// enumerateAddresses lists the unicast addresses of every operational adapter.
//
// GetAdaptersAddresses, not net.Interfaces(): the stdlib exposes neither the
// interface metric nor the presence of a default gateway, which are precisely
// what makes the choice between several addresses deterministic instead of
// heuristic (plan: no name-matching on "vEthernet").
func enumerateAddresses() ([]rawAddress, error) {
	size := uint32(initialAdapterBufSize)
	for range adapterBufAttempts {
		// Allocated as a slice of the struct, not of bytes: a []byte would be
		// correctly aligned for these 64-bit fields only by luck of the
		// allocator. The API writes into memory we own, so the linked list
		// below — and the net.IP slices pointing into it — stay valid for as
		// long as the GC sees them referenced. Nothing to free.
		buf := make([]windows.IpAdapterAddresses,
			size/uint32(unsafe.Sizeof(windows.IpAdapterAddresses{}))+1)
		head := &buf[0]

		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, gaaFlags, 0, head, &size)
		switch {
		case err == nil:
			return collectAddresses(head), nil
		case errors.Is(err, windows.ERROR_NO_DATA):
			// No adapter matches — a machine with every NIC disabled. Empty,
			// not an error.
			return nil, nil
		case !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		// size now holds the length the API wants; grow and retry. A loop
		// rather than a single retry: an adapter appearing in between (a VPN
		// coming up, a dock being plugged) can push the requirement up again.
	}
	return nil, fmt.Errorf(
		"GetAdaptersAddresses: buffer still too small after %d attempts", adapterBufAttempts)
}

// collectAddresses walks the adapter list and keeps the addresses of the
// adapters that can carry traffic.
func collectAddresses(head *windows.IpAdapterAddresses) []rawAddress {
	var out []rawAddress
	for ad := head; ad != nil; ad = ad.Next {
		// Only adapters that are actually up: a disconnected NIC keeps its
		// static address and a disabled one its last DHCP lease, and reporting
		// either would name the machine by an address nobody can reach.
		if ad.OperStatus != windows.IfOperStatusUp {
			continue
		}
		// Loopback is filtered by address anyway; tunnel pseudo-interfaces
		// (Teredo, ISATAP, 6to4) are dropped whole — they carry addresses that
		// designate nothing on the LAN.
		if ad.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || ad.IfType == windows.IF_TYPE_TUNNEL {
			continue
		}
		hasGateway := ad.FirstGatewayAddress != nil
		// Copied out of the fixed-size array rather than sliced in place: the
		// buffer stays alive as long as the returned addresses reference it,
		// and a MAC is six bytes — not worth pinning fifteen kilobytes for.
		var mac net.HardwareAddr
		if n := ad.PhysicalAddressLength; n > 0 && int(n) <= len(ad.PhysicalAddress) {
			mac = append(net.HardwareAddr(nil), ad.PhysicalAddress[:n]...)
		}

		for ua := ad.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := ua.Address.IP()
			if ip == nil {
				continue // neither AF_INET nor AF_INET6
			}
			// Metric and interface index are per-family on an adapter.
			metric, index := ad.Ipv4Metric, ad.IfIndex
			if ip.To4() == nil {
				metric, index = ad.Ipv6Metric, ad.Ipv6IfIndex
			}
			out = append(out, rawAddress{
				IP:  ip,
				MAC: mac,
				// The mask, straight from Windows. Per address and not per
				// adapter — two addresses on one NIC can sit on two different
				// prefixes — which is why it is read here and not above.
				PrefixLen:  ua.OnLinkPrefixLength,
				IfIndex:    index,
				Metric:     metric,
				HasGateway: hasGateway,
			})
		}
	}
	return out
}

// ipAdapterDHCPEnabled is IP_ADAPTER_DHCP_ENABLED from iptypes.h. Not exported
// by x/sys/windows, and one bit is not worth a dependency.
const ipAdapterDHCPEnabled = 0x0004

// enumerateAdapters lists every adapter for the inventory — including the ones
// that are down, which is precisely what makes it a different walk from
// collectAddresses above rather than a widening of it.
//
// The same buffer dance, deliberately repeated rather than factored out with
// collectAddresses behind a flag: the two differ in what they keep and in what
// they read off each adapter, and a shared walk parameterised by a boolean is
// how the address election — validated on a real machine, with five APIPA
// addresses and two Hyper-V switches to get wrong — would quietly change one day.
func enumerateAdapters() ([]rawAdapter, error) {
	size := uint32(initialAdapterBufSize)
	for range adapterBufAttempts {
		buf := make([]windows.IpAdapterAddresses,
			size/uint32(unsafe.Sizeof(windows.IpAdapterAddresses{}))+1)
		head := &buf[0]

		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, gaaFlags, 0, head, &size)
		switch {
		case err == nil:
			return collectAdapters(head), nil
		case errors.Is(err, windows.ERROR_NO_DATA):
			return nil, nil
		case !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
	return nil, fmt.Errorf(
		"GetAdaptersAddresses: buffer still too small after %d attempts", adapterBufAttempts)
}

// collectAdapters walks the adapter list, keeping one entry per adapter.
//
// Loopback is dropped and nothing else is: a disconnected NIC and a Hyper-V
// switch are both part of what this machine has, and hiding them would make the
// inventory disagree with the Device Manager an administrator is looking at.
func collectAdapters(head *windows.IpAdapterAddresses) []rawAdapter {
	var out []rawAdapter
	for ad := head; ad != nil; ad = ad.Next {
		if ad.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		a := rawAdapter{
			Name:      windows.UTF16PtrToString(ad.Description),
			IfType:    ad.IfType,
			SpeedBits: ad.TransmitLinkSpeed,
			Up:        ad.OperStatus == windows.IfOperStatusUp,
			DHCP:      ad.Flags&ipAdapterDHCPEnabled != 0,
		}
		if n := ad.PhysicalAddressLength; n > 0 && int(n) <= len(ad.PhysicalAddress) {
			a.MAC = append(net.HardwareAddr(nil), ad.PhysicalAddress[:n]...)
		}
		if gw := ad.FirstGatewayAddress; gw != nil {
			if ip := gw.Address.IP(); ip != nil {
				a.Gateway = ip.String()
			}
		}
		for ua := ad.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := ua.Address.IP()
			if ip == nil {
				continue
			}
			a.Addresses = append(a.Addresses, ip)
			a.PrefixLens = append(a.PrefixLens, ua.OnLinkPrefixLength)
		}
		out = append(out, a)
	}
	return out
}
