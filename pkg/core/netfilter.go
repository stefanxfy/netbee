package core

import "fmt"

// Netfilter 钩子点映射
var NFHookNames = map[uint8]string{
	0: "PRE_ROUTING",
	1: "LOCAL_IN",
	2: "FORWARD",
	3: "LOCAL_OUT",
	4: "POST_ROUTING",
}

// nf_hook_slow 返回值映射
var NFHookSlowReturnNames = map[int8]string{
	1:  "ACCEPT", // okfn() 需要被调用者执行，数据包被接受
	-1: "DROP",   // -EPERM (NF_DROP)
	0:  "OTHER",  // 其他情况
}

// FormatNFInfo 格式化 Netfilter 信息为 "nf_hook:verdict" 格式
func FormatNFInfo(nfHook uint8, verdict int8) string {
	hookName := NFHookNames[nfHook]
	verdictName := NFHookSlowReturnNames[verdict]
	
	// 如果钩子点或判决结果未知，显示原始值
	if hookName == "" {
		hookName = fmt.Sprintf("UNKNOWN(%d)", nfHook)
	}
	if verdictName == "" {
		verdictName = fmt.Sprintf("UNKNOWN(%d)", verdict)
	}
	
	return fmt.Sprintf("%s:%s", hookName, verdictName)
}

// FormatNFHookSlowInfo 格式化 nf_hook_slow 信息
func FormatNFHookSlowInfo(nfHook uint8, returnValue int8) string {
	hookName := NFHookNames[nfHook]
	returnName := NFHookSlowReturnNames[returnValue]
	
	// 如果钩子点或返回值未知，显示原始值
	if hookName == "" {
		hookName = fmt.Sprintf("UNKNOWN(%d)", nfHook)
	}
	if returnName == "" {
		returnName = fmt.Sprintf("UNKNOWN(%d)", returnValue)
	}
	
	return fmt.Sprintf("%s:%s", hookName, returnName)
}

// GetNFHookName 获取 Netfilter 钩子点名称
func GetNFHookName(hook uint8) string {
	if name, exists := NFHookNames[hook]; exists {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", hook)
}

// GetNFVerdictName 获取 Netfilter 判决结果名称
func GetNFVerdictName(verdict int8) string {
	if name, exists := NFHookSlowReturnNames[verdict]; exists {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", verdict)
}
