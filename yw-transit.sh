#!/usr/bin/env bash

# ==========================================
# YW极致中转管理面板 (内核态 T0) - 完整版
# 支持 TCP / UDP / TCP+UDP 协议转发
# 适合：游戏加速、直播中转、高性能NAT
# ==========================================

# 修复 Windows 环境下拷贝带来的换行符问题
if [ -f "$0" ]; then
    sed -i 's/\r$//' "$0" 2>/dev/null
fi

# 颜色变量定义
R="\033[0m"
G="\033[32m"
Y="\033[33m"
H="\033[90m"
RED="\033[31m"
C="\033[36m"
B="\033[97m"

# 权限检查
[ "$(id -u)" -ne 0 ] && echo -e "${RED}请使用 root 用户运行此脚本！${R}" && exit 1

# 获取本机公网 IP
get_my_ip() {
    local ip
    ip=$(curl -4 -s --connect-timeout 3 https://ifconfig.me 2>/dev/null || \
         curl -4 -s --connect-timeout 3 https://checkip.amazonaws.com 2>/dev/null || \
         curl -4 -s --connect-timeout 3 https://api.ipify.org 2>/dev/null)
    echo "${ip:-未知IP}"
}

# 持久化保存 iptables 规则
save_rules() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save > /dev/null 2>&1
    elif [ -f /etc/redhat-release ] && command -v iptables-service >/dev/null 2>&1; then
        service iptables save > /dev/null 2>&1
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi
}

# 确保开启内核 IP 转发
ensure_forward() {
    if ! grep -q "^net.ipv4.ip_forward.*=.*1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p > /dev/null 2>&1
    fi
}

# 【防坑核心】直连推流/游戏必加：防止跨网段 MTU 不一致导致大包被静默丢弃
ensure_mss_clamp() {
    if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        save_rules
    fi
}

# ==========================================
# 核心功能 1：添加转发规则
# ==========================================
add_rule() {
    echo -e "${C}--- 添加内核态转发规则 ---${R}"
    
    # 1. 获取落地机 IP
    while true; do
        echo -e "${C}请输入落地机的真实 IP: ${R}"
        read -e -p "IP: " BACKEND_IP
        if [[ "$BACKEND_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then break; fi
        echo -e "${RED}IP 格式错误，请重新输入！${R}"
    done

    # 2. 获取落地机端口
    while true; do
        echo -e "${C}请输入落地机的监听端口: ${R}"
        read -e -p "端口: " BACKEND_PORT
        if [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] && [ "$BACKEND_PORT" -le 65535 ]; then break; fi
        echo -e "${RED}端口格式错误 (1-65535)，请重新输入！${R}"
    done

    # 3. 获取中转机暴露端口
    while true; do
        echo -e "${C}请输入中转机对外暴露的端口: ${R}"
        read -e -p "端口: " FRONTEND_PORT
        if [[ "$FRONTEND_PORT" =~ ^[0-9]+$ ]] && [ "$FRONTEND_PORT" -le 65535 ]; then break; fi
        echo -e "${RED}端口格式错误 (1-65535)，请重新输入！${R}"
    done

    # 4. 选择协议 (新增核心逻辑)
    echo -e "${C}请选择转发协议类型:${R}"
    echo -e "${G}1.${R} TCP (网页/常规服务)"
    echo -e "${G}2.${R} UDP (游戏/部分低延迟直播)"
    echo -e "${G}3.${R} TCP + UDP 同时转发 (全协议游戏/全能模式)"
    read -e -p "协议选择 (默认 1): " PROTO_CHOICE
    
    case "$PROTO_CHOICE" in
        2) PROTOCOLS=("udp") ;;
        3) PROTOCOLS=("tcp" "udp") ;;
        *) PROTOCOLS=("tcp") ;; # 默认 TCP
    esac

    # 5. 执行添加逻辑
    ADDED=0
    for PROTO in "${PROTOCOLS[@]}"; do
        # 防止重复添加
        if iptables -t nat -C PREROUTING -p "$PROTO" --dport "$FRONTEND_PORT" -j DNAT --to-destination "$BACKEND_IP:$BACKEND_PORT" 2>/dev/null; then
            echo -e "${Y}[警告] 检测到 ${PROTO^^} 端口 $FRONTEND_PORT 的转发规则已存在，跳过。${R}"
        else
            iptables -t nat -A PREROUTING -p "$PROTO" --dport "$FRONTEND_PORT" -j DNAT --to-destination "$BACKEND_IP:$BACKEND_PORT"
            echo -e "${G}[成功] 已添加 ${PROTO^^} 转发规则${R}"
            ADDED=1
        fi
    done

    # 6. 处理 MASQUERADE (源地址转换，只需按目标IP存在一条即可)
    if [ $ADDED -eq 1 ]; then
        if ! iptables -t nat -C POSTROUTING -d "$BACKEND_IP" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -d "$BACKEND_IP" -j MASQUERADE
        fi
        save_rules
        echo -e "${G}========================================${R}"
        echo -e "${G}✅ 任务完成：${C}$(get_my_ip):${FRONTEND_PORT} -> ${BACKEND_IP}:${BACKEND_PORT} [${PROTOCOLS[*]}]${R}"
    else
        echo -e "${Y}未添加任何新规则。${R}"
    fi
}

# ==========================================
# 核心功能 2：删除转发规则
# ==========================================
del_rule() {
    echo -e "${C}--- 删除内核态转发规则 ---${R}"
    
    # 解析现有规则
    rules=()
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            rules+=("$line")
        fi
    done < <(iptables-save -t nat | awk '/PREROUTING/ && /DNAT/')

    if [ ${#rules[@]} -eq 0 ]; then
        echo -e "${H}当前没有任何转发规则。${R}"
        return
    fi

    # 显示规则列表
    echo -e "${Y}当前存在的转发规则：${R}"
    idx=1
    declare -A proto_map
    declare -A port_map
    declare -A dest_map
    
    for rule in "${rules[@]}"; do
        proto=$(echo "$rule" | awk '{for(i=1;i<=NF;i++) if($i=="-p") print $(i+1)}')
        port=$(echo "$rule" | awk '{for(i=1;i<=NF;i++) if($i=="--dport") print $(i+1)}')
        dest=$(echo "$rule" | awk '{for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}')
        
        proto_map[$idx]="$proto"
        port_map[$idx]="$port"
        dest_map[$idx]="$dest"
        echo -e "${G}[$idx]${R} 协议: ${B}${proto^^}${R}  监听端口: ${B}$port${R}  ->  落地目标: ${B}$dest${R}"
        ((idx++))
    done

    # 选择删除
    echo -e "${C}请输入要删除的规则序号 (回车取消): ${R}"
    read -e -p "序号: " sel
    
    if [[ -z "$sel" ]] || ! [[ "$sel" =~ ^[0-9]+$ ]] || [ -z "${port_map[$sel]:-}" ]; then
        echo -e "${H}已取消删除。${R}"
        return
    fi

    del_proto="${proto_map[$sel]}"
    del_port="${port_map[$sel]}"
    del_dest="${dest_map[$sel]}"

    # 执行删除
    if iptables -t nat -D PREROUTING -p "$del_proto" --dport "$del_port" -j DNAT --to-destination "$del_dest" 2>/dev/null; then
        echo -e "${G}[成功] 已删除 ${del_proto^^} 端口 ${del_port} 的规则。${R}"
        
        # 智能清理：如果该落地IP不再有任何转发规则了，顺手删掉对应的 MASQUERADE，保持规则表干净
        if ! iptables-save -t nat | grep "PREROUTING" | grep -q "${del_dest%%:*}"; then
            iptables -t nat -D POSTROUTING -d "${del_dest%%:*}" -j MASQUERADE 2>/dev/null
            echo -e "${H}[清理] 已移除不再需要的 MASQUERADE 规则。${R}"
        fi
        
        save_rules
    else
        echo -e "${RED}删除失败，可能规则已发生变动。${R}"
    fi
}

# ==========================================
# 核心功能 3：查看转发规则 (优化聚合显示)
# ==========================================
view_rules() {
    echo -e "${C}--- 当前中转转发规则清单 ---${R}"
    
    # 1. 提取所有规则
    rules=()
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            rules+=("$line")
        fi
    done < <(iptables-save -t nat | awk '/PREROUTING/ && /DNAT/')

    if [ ${#rules[@]} -eq 0 ]; then
        echo -e "${H}当前没有任何转发规则，是一片净土。${R}"
        return
    fi

    # 2. 聚合处理：如果同一个端口同时转发了 TCP 和 UDP，合并为一行显示
    declare -A rule_display
    for rule in "${rules[@]}"; do
        proto=$(echo "$rule" | awk '{for(i=1;i<=NF;i++) if($i=="-p") print $(i+1)}')
        port=$(echo "$rule" | awk '{for(i=1;i<=NF;i++) if($i=="--dport") print $(i+1)}')
        dest=$(echo "$rule" | awk '{for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}')
        key="${port}->${dest}"
        
        if [[ -z "${rule_display[$key]}" ]]; then
            rule_display[$key]="${proto^^}"
        else
            rule_display[$key]="${rule_display[$key]} + ${proto^^}"
        fi
    done

    # 3. 打印聚合后的结果
    local my_ip
    my_ip=$(get_my_ip)
    local idx=1
    
    for key in "${!rule_display[@]}"; do
        port="${key%%->*}"
        dest="${key##*->}"
        proto_str="${rule_display[$key]}"
        
        echo -e "${G}[$idx]${R} ${C}客户端连接${R} -> ${B}${my_ip}:${port}${R}  ${C}[${proto_str}]${R}  ${C}实际转发至${R} -> ${B}${dest}${R}"
        ((idx++))
    done
    
    echo -e "${H}----------------------------------------${R}"
    echo -e "${H}客户端链接生成方法：复制落地机链接，将 IP 改为 ${my_ip}，端口改为上方对应的监听端口${R}"
}

# ==========================================
# 核心功能 4：调用内核调优脚本
# ==========================================
run_kernel_tune() {
    echo -e "${C}正在拉取 kernel-smart.sh 魔改内核脚本...${R}"
    URL="https://raw.githubusercontent.com/wuy62380-ship-it/yw/main/kernel-smart.sh"
    FILE="/tmp/kernel-smart.sh"

    if ! curl -fsSL --connect-timeout 10 "$URL" -o "$FILE"; then
        echo -e "${RED}下载失败！请检查网络或 GitHub 链接是否可访问。${R}"
        read -rs -n 1 -p "按任意键返回..."
        return
    fi

    chmod +x "$FILE"
    echo -e "${Y}>>> 请在弹出的菜单中完成设置，完成后自动返回 <<<${R}"
    bash "$FILE"
    rm -f "$FILE"
    echo -e "${G}内核调优执行完毕！${R}"
    read -rs -n 1 -p "按任意键返回..."
}

# ==========================================
# 初始化环境
# ==========================================
ensure_forward
ensure_mss_clamp

# ==========================================
# 主循环菜单
# ==========================================
while true; do
    clear
    MYIP=$(get_my_ip)
    echo -e "${G}========================================${R}"
    echo -e "${G}    YW极致中转管理面板 (内核态 T0)     "
    echo -e "${G}========================================${R}"
    echo -e "本机 IPv4: ${C}${MYIP}${R}"
    echo -e "${G}========================================${R}"
    echo -e "${G}1.${R} 添加内核态转发规则 (TCP/UDP)"
    echo -e "${RED}2.${R} 删除内核态转发规则"
    echo -e "${H}3.${R} 查看当前转发规则"
    echo -e "${Y}4.${R} 运行 kernel-smart.sh 内核调优"
    echo -e "${G}========================================${R}"
    echo -e "${H}0.${R} 退出"
    echo -e "${G}========================================${R}"
    
    read -e -p "请输入选择: " c

    case $c in
        1) add_rule; read -rs -n 1 -p "按任意键继续..." ;;
        2) del_rule; read -rs -n 1 -p "按任意键继续..." ;;
        3) view_rules; read -rs -n 1 -p "按任意键继续..." ;;
        4) run_kernel_tune ;;
        0|"") exit 0 ;;
        *) echo -e "${RED}输入无效${R}"; sleep 1 ;;
    esac
done
