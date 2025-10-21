package core

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

// KernelSymbol represents a kernel symbol from /proc/kallsyms
type KernelSymbol struct {
	Address uint64
	Type    string
	Name    string
}

// SymbolResolver handles kernel symbol resolution
type SymbolResolver struct {
	symbols []KernelSymbol
}

// NewSymbolResolver creates a new symbol resolver and loads kernel symbols
func NewSymbolResolver() (*SymbolResolver, error) {
	resolver := &SymbolResolver{}
	err := resolver.loadKernelSymbols()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel symbols: %v", err)
	}
	return resolver, nil
}

// loadKernelSymbols loads symbols from /proc/kallsyms
func (sr *SymbolResolver) loadKernelSymbols() error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return fmt.Errorf("failed to open /proc/kallsyms: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		// Parse address
		address, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}

		// Parse type and name
		symbolType := parts[1]
		symbolName := parts[2]

		// Only include text symbols (functions)
		if symbolType == "t" || symbolType == "T" {
			sr.symbols = append(sr.symbols, KernelSymbol{
				Address: address,
				Type:    symbolType,
				Name:    symbolName,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/kallsyms: %v", err)
	}

	// Sort symbols by address for binary search
	sort.Slice(sr.symbols, func(i, j int) bool {
		return sr.symbols[i].Address < sr.symbols[j].Address
	})

	log.Printf("Loaded %d kernel symbols", len(sr.symbols))
	return nil
}

// ResolveAddress resolves a kernel address to a symbol name
func (sr *SymbolResolver) ResolveAddress(address uint64) string {
	if len(sr.symbols) == 0 {
		return fmt.Sprintf("0x%x", address)
	}

	// Binary search for the symbol with the largest address <= target address
	left, right := 0, len(sr.symbols)-1
	var bestMatch *KernelSymbol

	for left <= right {
		mid := (left + right) / 2
		symbol := &sr.symbols[mid]

		if symbol.Address <= address {
			bestMatch = symbol
			left = mid + 1
		} else {
			right = mid - 1
		}
	}

	if bestMatch != nil {
		offset := address - bestMatch.Address
		if offset == 0 {
			return bestMatch.Name
		}
		return fmt.Sprintf("%s+0x%x", bestMatch.Name, offset)
	}

	return fmt.Sprintf("0x%x", address)
}

// ResolveStackTrace resolves a stack trace to symbol names
func (sr *SymbolResolver) ResolveStackTrace(stackTrace [64]uint64, stackDepth uint32) string {
	if stackDepth == 0 {
		return ""
	}

	var resolvedStack []string
	for i := uint32(0); i < stackDepth && i < 64; i++ {
		if stackTrace[i] != 0 {
			symbol := sr.ResolveAddress(stackTrace[i])
			resolvedStack = append(resolvedStack, symbol)
		}
	}

	if len(resolvedStack) == 0 {
		return ""
	}

	return fmt.Sprintf(" Stack[%s]", strings.Join(resolvedStack, "->"))
}

// FormatStackTrace formats stack trace information for display
func FormatStackTrace(stackTrace [64]uint64, stackDepth uint32, symbolResolver *SymbolResolver) string {
	if stackDepth == 0 {
		return ""
	}
	
	// 如果符号解析器可用，使用符号解析
	if symbolResolver != nil {
		return symbolResolver.ResolveStackTrace(stackTrace, stackDepth)
	}
	
	// 否则显示原始地址
	var stackStr string
	for i := uint32(0); i < stackDepth && i < 64; i++ {
		if i > 0 {
			stackStr += "->"
		}
		stackStr += fmt.Sprintf("0x%x", stackTrace[i])
	}
	return fmt.Sprintf(" Stack[%s]", stackStr)
}
