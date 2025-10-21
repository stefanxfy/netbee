package http

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// htons 将主机字节序转换为网络字节序
func htons(i uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&i))[:])
}

// InterfaceManager 网络接口管理器
type InterfaceManager struct {
	sockets []int
}

// NewInterfaceManager 创建网络接口管理器
func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{
		sockets: make([]int, 0),
	}
}

// GetNetworkInterfaces 获取所有网络接口
func (im *InterfaceManager) GetNetworkInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %v", err)
	}

	// 过滤掉回环接口和无效接口
	var validInterfaces []net.Interface
	for _, iface := range interfaces {
		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 跳过虚拟接口（可选）
		if strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "veth") ||
			strings.HasPrefix(iface.Name, "br-") {
			continue
		}

		validInterfaces = append(validInterfaces, iface)
	}

	return validInterfaces, nil
}

// AttachToInterface 将socket filter附加到指定网络接口
func (im *InterfaceManager) AttachToInterface(ifaceName string, program *ebpf.Program) error {
	// 创建原始socket
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("创建原始socket失败: %v", err)
	}

	// 获取接口索引
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		syscall.Close(sock)
		return fmt.Errorf("获取接口 %s 失败: %v", ifaceName, err)
	}

	// 绑定socket到接口
	var sll unix.SockaddrLinklayer
	sll.Protocol = htons(unix.ETH_P_ALL)
	sll.Ifindex = iface.Index

	if err := unix.Bind(sock, &sll); err != nil {
		syscall.Close(sock)
		return fmt.Errorf("绑定socket到接口 %s 失败: %v", ifaceName, err)
	}

	// 获取程序文件描述符
	progFd := program.FD()
	if progFd < 0 {
		syscall.Close(sock)
		return fmt.Errorf("获取程序文件描述符失败")
	}

	// 附加eBPF程序到socket
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, progFd); err != nil {
		syscall.Close(sock)
		return fmt.Errorf("附加eBPF程序到接口 %s 失败: %v", ifaceName, err)
	}

	im.sockets = append(im.sockets, sock)
	return nil
}

// AttachToAllInterfaces 将socket filter附加到所有网络接口
func (im *InterfaceManager) AttachToAllInterfaces(program *ebpf.Program) error {
	interfaces, err := im.GetNetworkInterfaces()
	if err != nil {
		return err
	}

	var attachedCount int
	var errors []string

	for _, iface := range interfaces {
		err := im.AttachToInterface(iface.Name, program)
		if err != nil {
			errors = append(errors, fmt.Sprintf("接口 %s: %v", iface.Name, err))
			continue
		}
		attachedCount++
	}

	if attachedCount == 0 {
		return fmt.Errorf("没有成功附加到任何接口: %v", strings.Join(errors, "; "))
	}

	if len(errors) > 0 {
		return fmt.Errorf("部分接口附加失败 (成功: %d, 失败: %d): %v",
			attachedCount, len(errors), strings.Join(errors, "; "))
	}

	return nil
}

// AttachToSpecificInterfaces 将socket filter附加到指定的网络接口列表
func (im *InterfaceManager) AttachToSpecificInterfaces(interfaceNames []string, program *ebpf.Program) error {
	var attachedCount int
	var errors []string

	for _, ifaceName := range interfaceNames {
		err := im.AttachToInterface(ifaceName, program)
		if err != nil {
			errors = append(errors, fmt.Sprintf("接口 %s: %v", ifaceName, err))
			continue
		}
		attachedCount++
	}

	if attachedCount == 0 {
		return fmt.Errorf("没有成功附加到任何指定接口: %v", strings.Join(errors, "; "))
	}

	if len(errors) > 0 {
		return fmt.Errorf("部分指定接口附加失败 (成功: %d, 失败: %d): %v",
			attachedCount, len(errors), strings.Join(errors, "; "))
	}

	return nil
}

// Close 关闭所有socket
func (im *InterfaceManager) Close() error {
	var errors []string

	for _, sock := range im.sockets {
		if err := syscall.Close(sock); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("关闭socket时出错: %v", strings.Join(errors, "; "))
	}

	return nil
}

// GetAttachedInterfaces 获取已附加的接口信息
func (im *InterfaceManager) GetAttachedInterfaces() []string {
	return []string{fmt.Sprintf("已附加到 %d 个接口", len(im.sockets))}
}
