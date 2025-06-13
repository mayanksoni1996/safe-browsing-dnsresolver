package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type DNSResolver struct {
	cache map[string][]dns.RR
}

// API response structures
type StateModel struct {
	State                          string `json:"state"`
	DomainName                     string `json:"domainName"`
	IPAddress                      string `json:"ipAddress"`
	AccessAllowed                  bool   `json:"accessAllowed"`
	AccessOverrideControlAvailable bool   `json:"accessOverrideControlAvailable"`
	StateExpiresAt                 string `json:"stateExpiresAt"`
}

type TyposquattingValidationResults struct {
	IsTyposquatted         bool   `json:"isTyposquatted"`
	DomainName             string `json:"domainName"`
	ClosestMatchingDomain  string `json:"closestMatchingDomain"`
	EditDistance           int    `json:"editDistance"`
	IsPhoneticMatch        bool   `json:"isPhoneticMatch"`
	PhoneticMatchingDomain string `json:"phoneticMatchingDomain"`
	PhoneticMatchType      string `json:"phoneticMatchType"`
}

type APIResponse struct {
	StateModel                     StateModel                      `json:"stateModel"`
	TyposquattingValidationResults *TyposquattingValidationResults `json:"typosquattingValidationResults,omitempty"`
}

// getEnv reads an environment variable or returns a default value if not set
func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}

// Get detection API URL from environment variable or use default
var detectionAPI = getEnv("DETECTION_API_URL", "https://safe-browsing-backend-dev.dev.ca-west-1.heimdallauth.com")

// checkDomain calls the detection API to check if a domain is safe to access
func checkDomain(domain string, clientIP string) (*APIResponse, error) {
	// Generate a UUID for the state parameter
	state := uuid.New().String()

	// Remove trailing dot from domain if present
	domain = strings.TrimSuffix(domain, ".")

	// Prepare the API endpoint
	apiEndpoint := fmt.Sprintf("%s/api/v1/check-domain", detectionAPI)

	var response *http.Response
	var err error

	// If client IP is available, make a POST request, otherwise make a GET request
	if clientIP != "" {
		// Prepare POST request body
		requestBody := map[string]string{
			"domainName": domain,
			"stateId":    state,
			"ipAddress":  clientIP,
		}
		jsonBody, err := json.Marshal(requestBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}

		// Make POST request
		response, err = http.Post(apiEndpoint, "application/json", bytes.NewBuffer(jsonBody))
	} else {
		// Prepare GET request with query parameters
		params := url.Values{}
		params.Add("domain", domain)
		params.Add("state", state)

		// Make GET request
		response, err = http.Get(apiEndpoint + "?" + params.Encode())
	}

	if err != nil {
		return nil, fmt.Errorf("failed to call detection API: %v", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Println("Error closing response body:", err)
		}
	}()

	// Read response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response: %v", err)
	}

	// Parse response
	var apiResponse APIResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API response: %v", err)
	}

	return &apiResponse, nil
}

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

	// Get client's IP address
	clientIP := ""
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP.String()
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	// Check domain with detection API
	apiResponse, err := checkDomain(domain, clientIP)
	if err != nil {
		fmt.Printf("Error checking domain with detection API: %v\n", err)
		// If we can't check with the API, proceed with normal resolution
		// This ensures DNS resolution still works even if the API is down
	}

	// Process API response if available
	if apiResponse != nil {
		// If access is not allowed, redirect to confirmation page
		if !apiResponse.StateModel.AccessAllowed {
			// Create a CNAME record pointing to the confirmation page
			confirmationURL := fmt.Sprintf("%s/confirmation?state=%s", detectionAPI, apiResponse.StateModel.State)
			fmt.Printf("Access not allowed, redirecting to: %s\n", confirmationURL)

			// Create a response message with a CNAME record
			m := new(dns.Msg)
			m.SetReply(r)

			// Create a CNAME record pointing to the confirmation page
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}
			cname.Target = confirmationURL

			m.Answer = []dns.RR{cname}

			// Send the response back to the client
			err = w.WriteMsg(m)
			if err != nil {
				fmt.Println("Error sending DNS response:", err)
			}
			return
		}

		// If typosquatting validation was performed and domain is typosquatted
		if apiResponse.TyposquattingValidationResults != nil && apiResponse.TyposquattingValidationResults.IsTyposquatted {
			fmt.Printf("Domain %s is typosquatted, closest match: %s\n",
				domain, apiResponse.TyposquattingValidationResults.ClosestMatchingDomain)
			// You might want to handle this case differently
		}
	}

	// If access is allowed or API check failed, resolve the domain normally
	answers, err := resolver.resolveDomain(domain)
	if err != nil {
		fmt.Println("Error resolving domain:", err)
		// Send a failed response (NXDOMAIN)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		err := w.WriteMsg(m)
		if err != nil {
			return
		}
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

	// Log the detection API URL being used
	log.Printf("Using detection API URL: %s", detectionAPI)

	// Create a new DNS server
	dns.HandleFunc(".", resolver.DNSHandler)

	// Start the DNS server on port 53
	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Println("DNS server is starting on port 53...")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}
