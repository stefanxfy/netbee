package core

import (
	"sync"
	"time"
)

// PacketEventGroup 相同 packet ID 的事件组
type PacketEventGroup struct {
	Events    []*SoEvent
	FirstTime time.Time // 第一个事件的时间戳（用于排序）
	LastTime  time.Time
	mu        sync.Mutex
}

// PacketKey 包的唯一标识键（复合键）
type PacketKey struct {
	PacketID uint64
	TcpSeq   uint32 // TCP 序列号，用于区分不同的包
}

// PacketMerger 包合并器
type PacketMerger struct {
	groups    map[PacketKey]*PacketEventGroup
	mu        sync.RWMutex
	timeout   time.Duration
	flushChan chan PacketKey
}

// NewPacketMerger 创建包合并器
func NewPacketMerger(timeout time.Duration) *PacketMerger {
	return &PacketMerger{
		groups:    make(map[PacketKey]*PacketEventGroup),
		timeout:   timeout,
		flushChan: make(chan PacketKey, 1000),
	}
}

// getPacketKey 获取包的唯一标识键（内部函数）
func getPacketKey(event *SoEvent) PacketKey {
	return PacketKey{
		PacketID: event.PacketID,
		TcpSeq:   event.TcpSeq, // 使用 TCP 序列号来区分不同的包
	}
}

// GetPacketKey 获取包的唯一标识键（导出函数，供外部使用）
func GetPacketKey(event *SoEvent) PacketKey {
	return getPacketKey(event)
}

// AddEvent 添加事件到合并器
// 返回是否应该立即打印（例如收到 kfree_skb 时）
func (pm *PacketMerger) AddEvent(event *SoEvent) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	key := getPacketKey(event)
	group, exists := pm.groups[key]

	if !exists {
		// 创建新的事件组
		now := time.Now()
		group = &PacketEventGroup{
			Events:    []*SoEvent{event},
			FirstTime: now, // 记录第一个事件的时间戳
			LastTime:  now,
		}
		pm.groups[key] = group

		// 启动超时定时器
		go pm.scheduleFlush(key)
	} else {
		// 添加到现有事件组
		group.mu.Lock()
		group.Events = append(group.Events, event)
		group.LastTime = time.Now()
		group.mu.Unlock()
	}

	// 检查是否是结束函数（如 kfree_skb），如果是则立即返回 true
	funcName := event.GetFunctionName()
	if funcName == "kfree_skb" || funcName == "__kfree_skb" {
		return true
	}

	return false
}

// scheduleFlush 安排超时刷新
func (pm *PacketMerger) scheduleFlush(key PacketKey) {
	time.Sleep(pm.timeout)

	pm.mu.RLock()
	group, exists := pm.groups[key]
	pm.mu.RUnlock()

	if exists {
		// 检查是否真的超时了（可能在这期间有新事件到达）
		group.mu.Lock()
		elapsed := time.Since(group.LastTime)
		group.mu.Unlock()

		if elapsed >= pm.timeout {
			pm.flushChan <- key
		}
	}
}

// GetAndRemoveGroup 获取并移除事件组
func (pm *PacketMerger) GetAndRemoveGroup(key PacketKey) *PacketEventGroup {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	group, exists := pm.groups[key]
	if !exists {
		return nil
	}

	delete(pm.groups, key)
	return group
}

// GetFlushChan 获取刷新通道
func (pm *PacketMerger) GetFlushChan() <-chan PacketKey {
	return pm.flushChan
}

// GetFirstTime 获取事件组的第一个事件时间戳（用于排序）
func (g *PacketEventGroup) GetFirstTime() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.FirstTime
}

// FormatMergedInfo 格式化合并后的信息
// 函数链：所有函数名用 "->" 连接
// Info 信息：使用最后一个事件的信息，但函数名替换为函数链
// 返回合并后的 Info 字符串和最后一个事件（用于格式化输出）
func FormatMergedInfo(group *PacketEventGroup, symbolResolver *SymbolResolver) (string, *SoEvent) {
	if group == nil {
		return "", nil
	}

	group.mu.Lock()
	defer group.mu.Unlock()

	if len(group.Events) == 0 {
		return "", nil
	}

	// 构建函数链
	var funcChain []string
	for _, event := range group.Events {
		funcName := event.GetFunctionName()
		if funcName != "" {
			funcChain = append(funcChain, funcName)
		}
	}

	// 使用最后一个事件的信息
	lastEvent := group.Events[len(group.Events)-1]

	// 获取最后一个事件的 Info 信息
	info := lastEvent.FormatEventInfo(symbolResolver)

	// 构建函数链字符串
	chainStr := ""
	if len(funcChain) > 0 {
		chainStr = joinStrings(funcChain, "->")
	}

	// 替换 Info 中的单个函数名为函数链
	// FormatEventInfo 中的函数名格式是 [funcName]，我们需要替换为 [func1->func2->...]
	lastFuncName := lastEvent.GetFunctionName()
	if lastFuncName != "" {
		// 将 [funcName] 替换为 [func1->func2->...]
		oldPattern := "[" + lastFuncName + "]"
		newPattern := "[" + chainStr + "]"
		info = replaceFirst(info, oldPattern, newPattern)
	} else if chainStr != "" {
		// 如果没有找到函数名，直接添加函数链
		info += " [" + chainStr + "]"
	}

	// 移除 ID 信息（包合并后不需要显示 ID）
	// ID 格式：ID:数字，可能出现在不同位置
	info = removeIDFromInfo(info)

	return info, lastEvent
}

// replaceFirst 替换字符串中第一次出现的模式
func replaceFirst(s, old, new string) string {
	if len(old) == 0 || len(s) < len(old) {
		return s
	}

	// 简单的字符串替换，只替换第一次出现
	idx := -1
	for i := 0; i <= len(s)-len(old); i++ {
		if s[i:i+len(old)] == old {
			idx = i
			break
		}
	}

	if idx == -1 {
		return s
	}

	return s[:idx] + new + s[idx+len(old):]
}

// joinStrings 连接字符串数组
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// removeIDFromInfo 从 Info 字符串中移除 ID 信息
func removeIDFromInfo(info string) string {
	// 查找 "ID:" 并移除 ID:数字 部分
	// 注意：要区分 "ID:" 和 "PID:"，只移除 "ID:" 后跟数字的情况
	result := info

	// 查找 "ID:" 的位置（但排除 "PID:"）
	for {
		idx := -1
		for i := 0; i <= len(result)-3; i++ {
			if result[i:i+3] == "ID:" {
				// 检查前面是否是 "P"，如果是则跳过（这是 "PID:"）
				if i > 0 && result[i-1] == 'P' {
					continue
				}
				idx = i
				break
			}
		}

		if idx == -1 {
			break // 没有找到 ID:
		}

		// 找到 ID: 后面的数字结束位置（空格、制表符或字符串结束）
		endIdx := idx + 3 // ID: 之后
		for endIdx < len(result) {
			c := result[endIdx]
			if c == ' ' || c == '\t' {
				break
			}
			// 如果不是数字，停止
			if c < '0' || c > '9' {
				break
			}
			endIdx++
		}

		// 移除 ID:数字 部分（包括前面的空格）
		// 检查前面是否有空格
		startIdx := idx
		if idx > 0 && result[idx-1] == ' ' {
			startIdx = idx - 1
		}

		// 移除从 startIdx 到 endIdx 的部分
		if endIdx < len(result) {
			// 如果后面有空格，保留一个空格
			if result[endIdx] == ' ' {
				result = result[:startIdx] + " " + result[endIdx+1:]
			} else {
				result = result[:startIdx] + result[endIdx:]
			}
		} else {
			// 字符串结束，移除 ID:数字 和前面的空格
			if startIdx < len(result) {
				result = result[:startIdx]
			}
		}
	}

	return result
}
