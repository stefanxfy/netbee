package core

import (
	"fmt"
	"strings"
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
	return FormatMergedInfoWithRetransmission(group, symbolResolver, nil, true)
}

// FormatMergedInfoWithRetransmission 格式化合并后的信息（支持重传检测）
// 如果 retransmissionDetector 不为 nil，会检测重传并在 Seq 和 Ack 上应用红色
// colorEnabled 指示是否启用颜色输出
func FormatMergedInfoWithRetransmission(group *PacketEventGroup, symbolResolver *SymbolResolver, retransmissionDetector *RetransmissionDetector, colorEnabled bool) (string, *SoEvent) {
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

	// 应用颜色格式化（RST 标志、重传检测、NF DROP 等）
	// 注意：这里直接使用 ANSI 颜色代码，避免循环依赖
	// 重传检测应该始终执行，不管颜色是否启用
	isRetransmission := false
	if lastEvent.IPProto == ProtocolTCP && retransmissionDetector != nil {
		isRetransmission = retransmissionDetector.IsRetransmission(lastEvent)
	}

	// 处理重传标记（无论颜色是否启用）
	if isRetransmission {
		// 添加 [TCP Retransmission] 标记（带颜色或不带颜色）
		if colorEnabled {
			info = applyRetransmissionColorToInfo(info, lastEvent)
		} else {
			info = applyRetransmissionInfoToInfo(info, lastEvent)
		}
	} else if colorEnabled {
		// 如果没有重传，且启用颜色，检查 RST 标志并应用红色
		if lastEvent.IPProto == ProtocolTCP {
			if lastEvent.TcpFlags&0x04 != 0 { // RST 标志
				info = applyRSTColorToInfo(info, lastEvent)
			}
		}
	}

	// 处理 NF DROP 颜色（对所有协议都适用，仅在启用颜色时）
	// 注意：如果已经应用了重传颜色，重传颜色处理中已经包含了 NF DROP 的颜色
	if colorEnabled && !isRetransmission && lastEvent.Verdict == -1 { // DROP
		info = applyNFDropColorToInfo(info)
	}

	return info, lastEvent
}

// applyRSTColorToInfo 在 Info 字符串中应用 RST 标志颜色
func applyRSTColorToInfo(info string, event *SoEvent) string {
	// 使用 ANSI 颜色代码，避免循环依赖
	const redStart = "\033[31m"
	const redEnd = "\033[0m"

	// 重新构建带颜色的 flags 字符串
	flagParts := make([]string, 0)
	flags := event.TcpFlags

	if flags&0x01 != 0 { // FIN
		flagParts = append(flagParts, "FIN")
	}
	if flags&0x02 != 0 { // SYN
		flagParts = append(flagParts, "SYN")
	}
	if flags&0x04 != 0 { // RST - 用红色显示
		flagParts = append(flagParts, redStart+"RST"+redEnd)
	}
	if flags&0x08 != 0 { // PSH
		flagParts = append(flagParts, "PSH")
	}
	if flags&0x10 != 0 { // ACK
		flagParts = append(flagParts, "ACK")
	}
	if flags&0x20 != 0 { // URG
		flagParts = append(flagParts, "URG")
	}
	if flags&0x40 != 0 { // ECE
		flagParts = append(flagParts, "ECE")
	}
	if flags&0x80 != 0 { // CWR
		flagParts = append(flagParts, "CWR")
	}

	var coloredFlags string
	if len(flagParts) == 0 {
		coloredFlags = "NONE"
	} else {
		coloredFlags = strings.Join(flagParts, ",")
	}

	// 查找并替换 flags 部分
	// 格式通常是：端口->端口 ID:数字 flags Seq:数字 Ack:数字 ...
	// 我们需要找到 flags 的位置并替换
	// 使用 GetTcpFlagsString 获取原始 flags 字符串
	originalFlags := GetTcpFlagsString(event.TcpFlags)

	// 替换 flags 字符串
	info = strings.Replace(info, originalFlags, coloredFlags, 1)

	// 处理 NF DROP 颜色（如果存在）
	if event.Verdict == -1 { // DROP
		dropPattern := ":DROP"
		dropReplacement := ":" + redStart + "DROP" + redEnd
		info = strings.Replace(info, dropPattern, dropReplacement, 1)
	}

	return info
}

// applyRetransmissionColorToInfo 在 Info 字符串中应用重传颜色（Seq 和 Ack 显示红色）
func applyRetransmissionColorToInfo(info string, event *SoEvent) string {
	// 导入 color 包来使用红色
	// 注意：这里需要避免循环依赖，所以直接使用 ANSI 颜色代码
	const redStart = "\033[31m"
	const redEnd = "\033[0m"

	// 在 Info 最前面添加红色的 [TCP Retransmission] 标记
	retransmissionTag := redStart + "[TCP Retransmission]" + redEnd
	info = retransmissionTag + " " + info

	// 处理 RST 标志的颜色（如果存在）
	if event.TcpFlags&0x04 != 0 { // RST 标志
		// 重新构建带颜色的 flags 字符串
		flagParts := make([]string, 0)
		flags := event.TcpFlags

		if flags&0x01 != 0 { // FIN
			flagParts = append(flagParts, "FIN")
		}
		if flags&0x02 != 0 { // SYN
			flagParts = append(flagParts, "SYN")
		}
		if flags&0x04 != 0 { // RST - 用红色显示
			flagParts = append(flagParts, redStart+"RST"+redEnd)
		}
		if flags&0x08 != 0 { // PSH
			flagParts = append(flagParts, "PSH")
		}
		if flags&0x10 != 0 { // ACK
			flagParts = append(flagParts, "ACK")
		}
		if flags&0x20 != 0 { // URG
			flagParts = append(flagParts, "URG")
		}
		if flags&0x40 != 0 { // ECE
			flagParts = append(flagParts, "ECE")
		}
		if flags&0x80 != 0 { // CWR
			flagParts = append(flagParts, "CWR")
		}

		var coloredFlags string
		if len(flagParts) == 0 {
			coloredFlags = "NONE"
		} else {
			coloredFlags = strings.Join(flagParts, ",")
		}

		// 替换 flags 字符串
		originalFlags := GetTcpFlagsString(event.TcpFlags)
		info = strings.Replace(info, originalFlags, coloredFlags, 1)
	}

	// 替换 Seq:数字 中的数字为红色
	seqPattern := fmt.Sprintf("Seq:%d", event.TcpSeq)
	seqReplacement := fmt.Sprintf("Seq:%s%d%s", redStart, event.TcpSeq, redEnd)
	info = strings.Replace(info, seqPattern, seqReplacement, 1)

	// 替换 Ack:数字 中的数字为红色
	ackPattern := fmt.Sprintf("Ack:%d", event.TcpAck)
	ackReplacement := fmt.Sprintf("Ack:%s%d%s", redStart, event.TcpAck, redEnd)
	info = strings.Replace(info, ackPattern, ackReplacement, 1)

	// 处理 NF DROP 颜色（如果存在）
	if event.Verdict == -1 { // DROP
		dropPattern := ":DROP"
		dropReplacement := ":" + redStart + "DROP" + redEnd
		info = strings.Replace(info, dropPattern, dropReplacement, 1)
	}

	return info
}

// applyRetransmissionInfoToInfo 在 Info 字符串中应用重传标记（不带颜色）
func applyRetransmissionInfoToInfo(info string, event *SoEvent) string {
	// 在 Info 最前面添加 [TCP Retransmission] 标记（不带颜色）
	retransmissionTag := "[TCP Retransmission]"
	info = retransmissionTag + " " + info

	return info
}

// applyNFDropColorToInfo 在 Info 字符串中应用 NF DROP 颜色（DROP 显示红色）
func applyNFDropColorToInfo(info string) string {
	// 使用 ANSI 颜色代码，避免循环依赖
	const redStart = "\033[31m"
	const redEnd = "\033[0m"

	// 查找并替换 ":DROP" 为 ":红色DROP"
	// 格式通常是：... NF:LOCAL_IN:DROP 或 NF:POST_ROUTING:DROP
	// 我们需要将 ":DROP" 替换为 ":红色DROP"
	dropPattern := ":DROP"
	dropReplacement := ":" + redStart + "DROP" + redEnd
	info = strings.Replace(info, dropPattern, dropReplacement, 1)

	return info
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
