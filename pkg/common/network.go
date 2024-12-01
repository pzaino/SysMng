package common

import "net"

// GetHostIP returns the host IP address
func GetHostIP() string {
	hostIP := ""
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return hostIP
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip.IsGlobalUnicast() {
			hostIP = ip.String()
			break
		}
	}
	return hostIP
}
