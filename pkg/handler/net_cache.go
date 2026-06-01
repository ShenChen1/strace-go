package handler

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	netCacheLock  sync.Mutex
	netCache      map[string]string // maps "tcp:12345" to "127.0.0.1:80->10.0.0.1:1234"
	netCacheValid time.Time
)

// parseHexIP parses hex IP address format used in /proc/net/tcp
func parseHexIP(hexStr string) string {
	parts := strings.Split(hexStr, ":")
	if len(parts) != 2 {
		return hexStr
	}
	ipHex, portHex := parts[0], parts[1]
	port, _ := strconv.ParseUint(portHex, 16, 16)
	if len(ipHex) == 8 {
		// IPv4
		ip, _ := strconv.ParseUint(ipHex, 16, 32)
		return fmt.Sprintf("%d.%d.%d.%d:%d", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff, port)
	}
	if len(ipHex) == 32 {
		// IPv6
		var p [8]uint16
		for i := 0; i < 8; i++ {
			v, _ := strconv.ParseUint(ipHex[i*4:i*4+4], 16, 16)
			// Endianness trickiness in procfs for ipv6
			p[i] = uint16((v>>8)&0xff | (v<<8)&0xff)
		}
		// In IPv6 procfs, words are in a weird order
		return fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], port)
	}
	return hexStr
}

func updateNetCacheLocked() {
	if time.Now().Before(netCacheValid) {
		return
	}
	netCache = make(map[string]string)
	
	files := []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}
	for _, f := range files {
		proto := "tcp"
		if strings.Contains(f, "udp") {
			proto = "udp"
		}
		file, err := os.Open(f)
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) < 10 || fields[0] == "sl" {
					continue
				}
				local := parseHexIP(fields[1])
				rem := parseHexIP(fields[2])
				inode := fields[9]
				
				if rem == "0.0.0.0:0" || rem == "[0:0:0:0:0:0:0:0]:0" {
					netCache[proto+":"+inode] = local
				} else {
					netCache[proto+":"+inode] = local + "->" + rem
				}
			}
			file.Close()
		}
	}

	// UNIX sockets
	if file, err := os.Open("/proc/net/unix"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 6 || fields[0] == "Num" {
				continue
			}
			inode := fields[6]
			if len(fields) > 7 {
				netCache["unix:"+inode] = "\"" + fields[7] + "\""
			} else {
				netCache["unix:"+inode] = ""
			}
		}
		file.Close()
	}

	netCacheValid = time.Now().Add(50 * time.Millisecond)
}

// IMPACT: getSocketInfo parses system net files to extract protocol-specific connection information for -yy.
func getSocketInfo(proto string, inode string) string {
	netCacheLock.Lock()
	defer netCacheLock.Unlock()
	updateNetCacheLocked()
	if val, ok := netCache[proto+":"+inode]; ok && val != "" {
		return val
	}
	return inode
}
