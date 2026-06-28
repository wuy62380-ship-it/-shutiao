#!/usr/bin/env bash

# ==========================================
# YW 全场景终极中转管理面板 (双引擎 T0)
# TCP/直播流 -> HAProxy + NOTRACK (稳如老狗)
# UDP/游戏流 -> iptables NAT (极致低延迟)
# ==========================================

if [ -f "$0" ]; then sed -i 's/\r$//' "$0" 2>/dev/null; fi

R="\033[0m"; G="\033[32m"; Y="\033[33m"; H="\033[90m"
RED="\033[31m"; C="\033[36m"; B="\033[97m"; P="\033[35m"

[ "$(id -u)" -ne 0 ] && echo -e "${RED}请使用 root 运行${R}" && exit 1

YW_CFG="/etc/haproxy/haproxy-yw.cfg"
MAIN_CFG="/etc/haproxy/haproxy.cfg"

# 获取本机公网 IP
get_my_ip() {
    local ip
    ip=$(curl -4 -s --connect-timeout 3 https://ifconfig.me 2>/dev/null || \
         curl -4 -s --connect-timeout 3 https://checkip.amazonaws.com 2>/dev/null || \
         curl -4 -s --connect-timeout 3 https://api.ipify.org 2>/dev/null)
    echo "${ip:-未知IP}"
}

# 持久化 iptables 规则
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

# 环境初始化：安装 HAProxy 并配置底层基础设施
init_env() {
    # 1. 检查并安装 HAProxy
    if ! command -v haproxy >/dev/null 2>&1; then
        echo -e "${Y}检测到未安装 HAProxy，正在自动安装...${R}"
        if [ -f /etc/debian_version ]; then
            apt-get update -qq && apt-get install -y -qq haproxy > /dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y -q haproxy > /dev/null 2>&1
        fi
        if ! command -v haproxy >/dev/null 2>&1; then
            echo -e "${RED}HAProxy 安装失败，请手动安装后重试！${R}"; exit 1
        fi
        echo -e "${G}HAProxy 安装成功！${R}"
    fi

    # 2. 开启内核转发
    if ! grep -q "^net.ipv4.ip_forward.*=.*1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p > /dev/null 2>&1
    fi

    # 3. 跨国大包防坑：MSS 钳制 (TCP直播必加)
    if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        save_rules
    fi

    # 4. 初始化 YW 专属配置文件，并在主配置中引入
    if [ ! -f "$YW_CFG" ]; then
        cat > "$YW_CFG" << 'EOF'
# ==========================================
# YW 面板自动生成的 HAProxy 配置
# 请勿手动修改，以免被面板覆盖
# ==========================================
EOF
    fi
    if ! grep -q "haproxy-yw.cfg" "$MAIN_CFG" 2>/dev/null; then
        echo -e "\n# YW Ultimate Transit Include\n\$INCLUDE ${YW_CFG}\n" >> "$MAIN_CFG"
    fi

    # 5. 确保 HAProxy 开机自启并应用一次配置
    systemctl enable haproxy > /dev/null 2>&1
    reload_haproxy
}

# 重载 HAProxy 配置（带语法检查）
reload_haproxy() {
    if haproxy -c -f "$MAIN_CFG" > /dev/null 2>&1; then
        systemctl reload haproxy > /dev/null 2>&1
        return 0
    else
        echo -e "${RED}HAProxy 配置语法错误，拒绝重载！${R}"
        return 1
    fi
}

# ==========================================
# 引擎 1：添加 HAProxy (TCP/直播) 规则
# ==========================================
add_haproxy() {
    echo -e "${P}--- 添加 TCP/直播转发 (HAProxy 稳定引擎) ---${R}"
    
    read -e -p "请输入落地机真实 IP: " BACKEND_IP
    [[ ! "$BACKEND_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo -e "${RED}IP 格式错误！${R}" && return

    read -e -p "请输入落地机端口: " BACKEND_PORT
    [[ ! "$BACKEND_PORT" =~ ^[0-9]+$ ]] && echo -e "${RED}端口错误！${R}" && return

    read -e -p "请输入中转机监听端口: " FRONTEND_PORT
    [[ ! "$FRONTEND_PORT" =~ ^[0-9]+$ ]] && echo -e "${RED}端口错误！${R}" && return

    # 防止端口冲突：检查该端口是否已被 iptables 的 TCP 规则占用
    if iptables -t nat -C PREROUTING -p tcp --dport "$FRONTEND_PORT" -j DNAT 2>/dev/null; then
        echo -e "${RED}冲突！端口 $FRONTEND_PORT 已被 iptables TCP 规则占用。${R}"; return
    fi

    # 检查 HAProxy 内是否已存在
    if grep -q "bind \*:${FRONTEND_PORT}" "$YW_CFG" 2>/dev/null; then
        echo -e "${Y}HAProxy 中端口 $FRONTEND_PORT 已存在。${R}"; return
    fi

    # 1. 核心：为该端口添加 NOTRACK，彻底抛弃 conntrack
    iptables -t raw -A PREROUTING -p tcp --dport "$FRONTEND_PORT" -j NOTRACK
    save_rules

    # 2. 追加 HAProxy 配置 (针对跨国直播优化了超时和缓冲区)
    cat >> "$YW_CFG" << EOF

# YW_RULE_START_${FRONTEND_PORT}
frontend fe_${FRONTEND_PORT}
    bind *:${FRONTEND_PORT}
    timeout client 2h
    default_backend be_${FRONTEND_PORT}

backend be_${FRONTEND_PORT}
    timeout connect 5s
    timeout server 2h
    balance roundrobin
    option tcp-check
    tcp-check connect
    server svr_${FRONTEND_PORT} ${BACKEND_IP}:${BACKEND_PORT} check inter 5s fall 3 rise 2
# YW_RULE_END_${FRONTEND_PORT}
EOF

    # 3. 语法检查并重载
    if reload_haproxy; then
        echo -e "${G}✅ 添加成功：${C}$(get_my_ip):${FRONTEND_PORT} -> ${BACKEND_IP}:${BACKEND_PORT} [HAProxy/TCP/NOTRACK]${R}"
    else
        # 如果失败，回滚操作
        echo -e "${RED}配置写入失败，正在回滚...${R}"
        iptables -t raw -D PREROUTING -p tcp --dport "$FRONTEND_PORT" -j NOTRACK 2>/dev/null
        sed -i "/# YW_RULE_START_${FRONTEND_PORT}/,/# YW_RULE_END_${FRONTEND_PORT}/d" "$YW_CFG"
        save_rules
    fi
}

# ==========================================
# 引擎 2：添加 iptables (UDP/游戏) 规则
# ==========================================
add_iptables() {
    echo -e "${C}--- 添加 UDP/游戏转发 (iptables 极速引擎) ---${R}"
    
    read -e -p "请输入落地机真实 IP: " BACKEND_IP
    [[ ! "$BACKEND_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo -e "${RED}IP 格式错误！${R}" && return

    read -e -p "请输入落地机端口: " BACKEND_PORT
    [[ ! "$BACKEND_PORT" =~ ^[0-9]+$ ]] && echo -e "${RED}端口错误！${R}" && return

    read -e -p "请输入中转机监听端口: " FRONTEND_PORT
    [[ ! "$FRONTEND_PORT" =~ ^[0-9]+$ ]] && echo -e "${RED}端口错误！${R}" && return

    # 防止端口冲突：检查该端口是否被 HAProxy 占用
    if grep -q "bind \*:${FRONTEND_PORT}" "$YW_CFG" 2>/dev/null; then
        echo -e "${RED}冲突！端口 $FRONTEND_PORT 已被 HAProxy 占用。${R}"; return
    fi

    # 强制走 UDP
    PROTO="udp"
    if iptables -t nat -C PREROUTING -p "$PROTO" --dport "$FRONTEND_PORT" -j DNAT --to-destination "$BACKEND_IP:$BACKEND_PORT" 2>/dev/null; then
        echo -e "${Y}UDP 端口 $FRONTEND_PORT 已存在。${R}"; return
    fi

    iptables -t nat -A PREROUTING -p "$PROTO" --dport "$FRONTEND_PORT" -j DNAT --to-destination "$BACKEND_IP:$BACKEND_PORT"
    
    if ! iptables -t nat -C POSTROUTING -d "$BACKEND_IP" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -d "$BACKEND_IP" -j MASQUERADE
    fi

    save_rules
    echo -e "${G}✅ 添加成功：${C}$(get_my_ip):${FRONTEND_PORT} -> ${BACKEND_IP}:${BACKEND_PORT} [iptables/UDP]${R}"
}

# ==========================================
# 统一删除规则
# ==========================================
del_rule() {
    echo -e "${C}--- 删除转发规则 ---${R}"
    rules=()
    rule_types=()

    # 收集 HAProxy 规则
    while IFS= read -r port; do
        if [[ -n "$port" ]]; then
            dest=$(grep -A5 "frontend fe_${port}" "$YW_CFG" | grep "server svr" | awk '{print $3}')
            rules+=("$port -> ${dest%%:*}")
            rule_types+=("haproxy")
        fi
    done < <(grep "YW_RULE_START" "$YW_CFG" | awk -F'_' '{print $NF}')

    # 收集 iptables UDP 规则
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            port=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--dport") print $(i+1)}')
            dest=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}')
            rules+=("$port -> ${dest%%:*}")
            rule_types+=("iptables")
        fi
    done < <(iptables-save -t nat | awk '/PREROUTING/ && /DNAT/ && /-p udp/')

    if [ ${#rules[@]} -eq 0 ]; then
        echo -e "${H}当前没有任何转发规则。${R}"; return
    fi

    echo -e "${Y}当前规则列表：${R}"
    idx=1
    declare -A port_map
    declare -A type_map
    for i in "${!rules[@]}"; do
        port_map[$idx]="${rules[$i]%% *}"
        type_map[$idx]="${rule_types[$i]}"
        if [ "${rule_types[$i]}" = "haproxy" ]; then
            echo -e "${G}[$idx]${R} [${P}HAProxy/TCP${R}] 端口: ${B}${port_map[$idx]}${R} -> ${rules[$i]#* }"
        else
            echo -e "${G}[$idx]${R} [${C}iptables/UDP${R}] 端口: ${B}${port_map[$idx]}${R} -> ${rules[$i]#* }"
        fi
        ((idx++))
    done

    read -e -p "请输入要删除的序号 (回车取消): " sel
    if [[ -z "$sel" ]] || ! [[ "$sel" =~ ^[0-9]+$ ]] || [ -z "${port_map[$sel]:-}" ]; then
        echo -e "${H}已取消。${R}"; return
    fi

    del_port="${port_map[$sel]}"
    del_type="${type_map[$sel]}"

    if [ "$del_type" = "haproxy" ]; then
        # 删除 NOTRACK
        iptables -t raw -D PREROUTING -p tcp --dport "$del_port" -j NOTRACK 2>/dev/null
        # 删除配置块
        sed -i "/# YW_RULE_START_${del_port}/,/# YW_RULE_END_${del_port}/d" "$YW_CFG"
        reload_haproxy
        save_rules
        echo -e "${G}✅ 已删除 HAProxy 端口 ${del_port} 的规则。${R}"
    else
        # 删除 iptables UDP 规则
        dest_full=$(iptables-save -t nat | awk -v p="$del_port" '/PREROUTING/ && /DNAT/ && /-p udp/ && $0 ~ ("--dport "p) {for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}')
        iptables -t nat -D PREROUTING -p udp --dport "$del_port" -j DNAT --to-destination "$dest_full" 2>/dev/null
        
        # 智能清理 MASQUERADE
        if ! iptables-save -t nat | grep "PREROUTING" | grep -q "${dest_full%%:*}"; then
            iptables -t nat -D POSTROUTING -d "${dest_full%%:*}" -j MASQUERADE 2>/dev/null
        fi
        save_rules
        echo -e "${G}✅ 已删除 iptables UDP 端口 ${del_port} 的规则。${R}"
    fi
}

# ==========================================
# 统一查看规则
# ==========================================
view_rules() {
    echo -e "${C}--- 全场景转发规则清单 ---${R}"
    my_ip=$(get_my_ip)
    idx=1
    has_rules=0

    # 显示 HAProxy 规则
    while IFS= read -r port; do
        if [[ -n "$port" ]]; then
            dest=$(grep -A5 "frontend fe_${port}" "$YW_CFG" | grep "server svr" | awk '{print $3}')
            echo -e "${G}[$idx]${R} [${P}HAProxy/TCP${R}] ${C}${my_ip}:${port}${R} -> ${B}${dest}${R}"
            has_rules=1; ((idx++))
        fi
    done < <(grep "YW_RULE_START" "$YW_CFG" | awk -F'_' '{print $NF}')

    # 显示 iptables 规则
    declare -A ipt_display
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            port=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--dport") print $(i+1)}')
            dest=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}')
            key="${port}->${dest}"
            ipt_display[$key]=1
        fi
    done < <(iptables-save -t nat | awk '/PREROUTING/ && /DNAT/ && /-p udp/')

    for key in "${!ipt_display[@]}"; do
        port="${key%%->*}"; dest="${key##*->}"
        echo -e "${G}[$idx]${R} [${C}iptables/UDP${R}] ${C}${my_ip}:${port}${R} -> ${B}${dest}${R}"
        has_rules=1; ((idx++))
    done

    [ $has_rules -eq 0 ] && echo -e "${H}当前没有任何转发规则。${R}"
}

# 运行外部内核调优
run_kernel_tune() {
    echo -e "${C}正在拉取 kernel-smart.sh...${R}"
    FILE="/tmp/kernel-smart.sh"
    if curl -fsSL --connect-timeout 10 "https://raw.githubusercontent.com/wuy62380-ship-it/yw/main/kernel-smart.sh" -o "$FILE"; then
        chmod +x "$FILE"
        bash "$FILE"
        rm -f "$FILE"
    else
        echo -e "${RED}下载失败！${R}"
    fi
    read -rs -n 1 -p "按任意键返回..."
}

# ==========================================
# 启动主程序
# ==========================================
init_env

while true; do
    clear
    MYIP=$(get_my_ip)
    echo -e "${G}========================================${R}"
    echo -e "${G}   YW 全场景终极中转面板 (双引擎 T0)   "
    echo -e "${G}========================================${R}"
    echo -e "本机 IP: ${C}${MYIP}${R}"
    echo -e "${G}----------------------------------------${R}"
    echo -e "${P}1.${R} 添加 TCP/直播转发 (HAProxy引擎)"
    echo -e "${C}2.${R} 添加 UDP/游戏转发 (iptables引擎)"
    echo -e "${RED}3.${R} 删除转发规则"
    echo -e "${H}4.${R} 查看所有转发规则"
    echo -e "${Y}5.${R} 运行 kernel-smart.sh 内核调优"
    echo -e "${G}========================================${R}"
    echo -e "${H}0.${R} 退出"
    echo -e "${G}========================================${R}"
    
    read -e -p "请输入选择: " c
    case $c in
        1) add_haproxy; read -rs -n 1 -p "按任意键继续..." ;;
        2) add_iptables; read -rs -n 1 -p "按任意键继续..." ;;
        3) del_rule; read -rs -n 1 -p "按任意键继续..." ;;
        4) view_rules; read -rs -n 1 -p "按任意键继续..." ;;
        5) run_kernel_tune ;;
        0|"") exit 0 ;;
        *) echo -e "${RED}输入无效${R}"; sleep 1 ;;
    esac
done
