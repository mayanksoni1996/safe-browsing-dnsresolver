package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"time"
)

type DNSResolver struct {
	cache map[string][]dns.RR
}

var detectionAPI = "https://threat-intel-dev.dev.ca-west-1.heimdallauth.com"

// resolveDomain resolves a given domain name and returns the results
func (resolver *DNSResolver) resolveDomain(domain string) ([]dns.RR, error) {
	// Check if the result is cached
	if cachedResult, exists := resolver.cache[domain]; exists {
		fmt.Println("Cache hit!")
		return cachedResult, nil
	}

	// Create a DNS message to query for A records
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Define a DNS client with a timeout
	c := &dns.Client{
		Timeout: 5 * time.Second,
	}

	// Use Google's public DNS server for resolution (8.8.8.8)
	response, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNS query: %v", err)
	}

	// Cache the result
	resolver.cache[domain] = response.Answer

	return response.Answer, nil
}

// DNSHandler handles incoming DNS requests and sends back responses
func (resolver *DNSResolver) DNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	// The domain queried by the client (e.g., example.com)
	domain := r.Question[0].Name

	fmt.Printf("Received DNS query for domain: %s\n", domain)

	// Resolve the domain
	answers, err := resolver.resolveDomain(domain)
	if err != nil {
		fmt.Println("Error resolving domain:", err)
		// Send a failed response (NXDOMAIN)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		w.WriteMsg(m)
		return
	}

	// Create a response message
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = answers

	// Send the response back to the client
	err = w.WriteMsg(m)
	if err != nil {
		fmt.Println("Error sending DNS response:", err)
	}
}

func main() {
	// Create a resolver with caching capabilities
	resolver := DNSResolver{cache: make(map[string][]dns.RR)}

	// Create a new DNS server
	dns.HandleFunc(".", resolver.DNSHandler)

	// Start the DNS server on port 53
	server := &dns.Server{Addr: ":53", Net: "udp"}
	fmt.Println("DNS server is starting on port 53...")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}
