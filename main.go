// mdns_local_to_lan_responder.go
package main

import (
	"bytes"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	ip        string
	expiresAt time.Time
}

var (
	cache   = make(map[string]*cacheEntry)
	cacheMu sync.RWMutex
)

func main() {
	go refreshCacheLoop()

	addr := net.UDPAddr{
		Port: 5353,
		IP:   net.IPv4zero,
	}
	conn, err := net.ListenUDP("udp4", &addr)
	if err != nil {
		log.Fatalf("Failed to bind: %v", err)
	}
	defer conn.Close()

	log.Println("Listening for mDNS queries on UDP 5353...")
	buf := make([]byte, 1024)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		if !bytes.Contains(buf[:n], []byte(".local")) {
			continue
		}

		name := extractName(buf[:n])
		if name == "" {
			continue
		}

		ip := getCachedIP(name)
		if ip == "" {
			log.Printf("No cached IP for %s", name)
			continue
		}

		response := buildFakeMDNSResponse(name+".local.", ip)
		conn.WriteToUDP(response, src)
	}
}

func extractName(data []byte) string {
	// Crude parsing: find label before ".local"
	parts := bytes.Split(data, []byte(".local"))
	if len(parts) == 0 {
		return ""
	}
	raw := strings.TrimSpace(string(parts[0]))
	lines := strings.Split(raw, "\n")
	last := lines[len(lines)-1]
	fields := strings.Fields(last)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func getCachedIP(name string) string {
	cacheMu.RLock()
	e, ok := cache[name]
	cacheMu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return ""
	}
	return e.ip
}

func refreshCacheLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		refreshCache()
		<-ticker.C
	}
}

func refreshCache() {
	names := []string{ /* fill with known hostnames */ }
	for _, local := range names {
		lan := strings.TrimSuffix(local, ".local") + ".lan"
		ips, err := net.LookupHost(lan)
		if err != nil || len(ips) == 0 {
			continue
		}
		cacheMu.Lock()
		cache[local] = &cacheEntry{
			ip:        ips[0],
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		cacheMu.Unlock()
		log.Printf("Refreshed %s -> %s", local, ips[0])
	}
}

func buildFakeMDNSResponse(name string, ip string) []byte {
	var buf bytes.Buffer

	buf.Write([]byte{0x00, 0x00}) // Transaction ID
	buf.Write([]byte{0x84, 0x00}) // Flags: standard response
	buf.Write([]byte{0x00, 0x00}) // QDCOUNT
	buf.Write([]byte{0x00, 0x01}) // ANCOUNT = 1
	buf.Write([]byte{0x00, 0x00}) // NSCOUNT
	buf.Write([]byte{0x00, 0x00}) // ARCOUNT

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			break
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00) // end of name

	buf.Write([]byte{0x00, 0x01})             // Type A
	buf.Write([]byte{0x00, 0x01})             // Class IN
	buf.Write([]byte{0x00, 0x00, 0x00, 0x3c}) // TTL 60s
	buf.Write([]byte{0x00, 0x04})             // RDLENGTH
	buf.Write(net.ParseIP(ip).To4())          // RDATA

	return buf.Bytes()
}
