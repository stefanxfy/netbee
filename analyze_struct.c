#include <stdio.h>
#include <stdint.h>

#define FUNCNAME_MAX_LEN 32
#define MAX_BODY_LENGTH 1024
#define MAX_URI_LENGTH 256
#define MAX_PARAMS_LENGTH 512
#define MAX_METHOD_LENGTH 16

struct http_event {
    // 基础网络信息
    uint32_t src_addr;      // 0
    uint32_t dst_addr;      // 4
    uint32_t ip_proto;      // 8
    uint8_t dst_mac[6];     // 12
    uint8_t ttl;            // 18
    uint32_t ifindex;       // 20 (对齐到4字节)
    uint16_t src_port;      // 24
    uint16_t dst_port;      // 26
    uint8_t tcp_flags;      // 28
    uint32_t tcp_seq;       // 32 (对齐到4字节)
    uint32_t tcp_ack;       // 36
    uint16_t tcp_len;       // 40
    uint16_t udp_len;       // 42
    char func_name[FUNCNAME_MAX_LEN];  // 44
    
    // HTTP特有字段
    uint8_t http_version;   // 76
    char method[MAX_METHOD_LENGTH];     // 80 (对齐到4字节)
    char request_uri[MAX_URI_LENGTH];   // 96
    char request_params[MAX_PARAMS_LENGTH]; // 352
    uint16_t status_code;   // 864
    uint16_t body_len;      // 866
    char response_body[MAX_BODY_LENGTH]; // 1024 (对齐到4字节)
    uint8_t rw;             // 2048
    uint64_t timestamp_ns;  // 2056 (对齐到8字节)
    
    // 大数据包处理字段
    uint8_t truncated;      // 2064
    uint32_t original_len;  // 2068 (对齐到4字节)
    uint8_t truncate_type;  // 2072
    uint8_t padding[3];     // 2073
};

int main() {
    printf("结构体大小: %zu 字节\n", sizeof(struct http_event));
    printf("func_name 偏移: %zu 字节\n", (size_t)&((struct http_event*)0)->func_name);
    printf("tcp_seq 偏移: %zu 字节\n", (size_t)&((struct http_event*)0)->tcp_seq);
    return 0;
}
