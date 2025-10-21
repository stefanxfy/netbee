package core

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// MacVendorEntry represents a MAC address vendor entry
type MacVendorEntry struct {
	MacPrefix string // MAC address prefix (e.g., "00:18:82")
	Vendor    string // Vendor name (e.g., "HuaweiTechno")
}

// MacResolver handles MAC address to vendor name resolution
type MacResolver struct {
	vendorMap map[string]string // MAC prefix -> vendor name mapping
	mutex     sync.RWMutex      // Read-write mutex for thread safety
}

var (
	macResolver *MacResolver
	once        sync.Once
)

// NewMacResolver creates a new MAC resolver instance
func NewMacResolver() (*MacResolver, error) {
	resolver := &MacResolver{
		vendorMap: make(map[string]string),
	}
	
	err := resolver.loadManufFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load manuf file: %v", err)
	}
	
	return resolver, nil
}

// GetMacResolver returns a singleton instance of MacResolver
func GetMacResolver() (*MacResolver, error) {
	var err error
	once.Do(func() {
		macResolver, err = NewMacResolver()
	})
	return macResolver, err
}

// loadManufFile loads the manuf.txt file and builds the vendor mapping
func (mr *MacResolver) loadManufFile() error {
	// Try multiple possible paths for manuf.txt
	possiblePaths := []string{
		"./target/manuf.txt",
		"target/manuf.txt",
		"./manuf.txt",
		"manuf.txt",
	}
	
	var manufPath string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			manufPath = path
			break
		}
	}
	
	if manufPath == "" {
		return fmt.Errorf("manuf.txt file not found in any of the expected locations")
	}
	
	file, err := os.Open(manufPath)
	if err != nil {
		return fmt.Errorf("failed to open manuf file %s: %v", manufPath, err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineCount := 0
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineCount++
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse the line: MAC_PREFIX\tVENDOR_NAME
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue // Skip malformed lines
		}
		
		macPrefix := strings.TrimSpace(parts[0])
		vendorName := strings.TrimSpace(parts[1])
		
	// Validate MAC prefix format (should be like "00:18:82")
	if isValidMacPrefix(macPrefix) {
		// Store in uppercase for consistent lookup
		mr.vendorMap[strings.ToUpper(macPrefix)] = vendorName
	}
	}
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading manuf file: %v", err)
	}
	
	fmt.Printf("Loaded %d MAC vendor entries from %s\n", len(mr.vendorMap), manufPath)
	return nil
}

// isValidMacPrefix validates if the string is a valid MAC address prefix
func isValidMacPrefix(prefix string) bool {
	// Check if it's in the format "XX:XX:XX" (3 octets)
	parts := strings.Split(prefix, ":")
	if len(parts) != 3 {
		return false
	}
	
	// Check if each part is a valid hex byte
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		// Simple hex validation
		for _, char := range part {
			if !((char >= '0' && char <= '9') || 
				 (char >= 'A' && char <= 'F') || 
				 (char >= 'a' && char <= 'f')) {
				return false
			}
		}
	}
	return true
}

// ResolveMacAddress resolves a MAC address to vendor name
func (mr *MacResolver) ResolveMacAddress(mac [6]uint8) string {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()
	
	// Convert MAC address to string format
	macStr := MacToString(mac)
	
	// Extract the first 3 octets (OUI - Organizationally Unique Identifier)
	parts := strings.Split(macStr, ":")
	if len(parts) < 3 {
		return macStr // Return original MAC if format is invalid
	}
	
	oui := strings.ToUpper(strings.Join(parts[:3], ":"))
	
	// Look up the vendor name
	if vendor, exists := mr.vendorMap[oui]; exists {
		return fmt.Sprintf("%s(%s)", macStr, vendor)
	}
	
	// Return original MAC if no vendor found
	return macStr
}

// ResolveMacString resolves a MAC address string to vendor name
func (mr *MacResolver) ResolveMacString(macStr string) string {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()
	
	// Extract the first 3 octets (OUI)
	parts := strings.Split(macStr, ":")
	if len(parts) < 3 {
		return macStr // Return original MAC if format is invalid
	}
	
	oui := strings.ToUpper(strings.Join(parts[:3], ":"))
	
	// Look up the vendor name
	if vendor, exists := mr.vendorMap[oui]; exists {
		return fmt.Sprintf("%s(%s)", macStr, vendor)
	}
	
	// Return original MAC if no vendor found
	return macStr
}

// GetVendorCount returns the number of loaded vendor entries
func (mr *MacResolver) GetVendorCount() int {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()
	return len(mr.vendorMap)
}

// GetVendorByOUI returns the vendor name for a given OUI
func (mr *MacResolver) GetVendorByOUI(oui string) (string, bool) {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()
	vendor, exists := mr.vendorMap[oui]
	return vendor, exists
}
