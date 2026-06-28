#!/usr/bin/env bash

# ==========================================
# YW 全场景终极中转管理面板 (生产级封神版)
# TCP/直播流 -> HAProxy + NOTRACK
# UDP/游戏流 -> iptables NAT
# 底层：1G-64G 内存自适应 + OS级防穿透引擎
# ==========================================

if [ -f "$0" ]; then sed -i 's/\r$//' "$0" 2>/dev/null; fi

R="\033[0m"; G="\033[32m"; Y="\033[33m"; H="\033[90m"
RED="\033[31m"; C="\033[36m"; B="\033[97m"; P="\033[35m"

[ "$(id -u)" -ne 0 ] && echo -e "${RED}请使用 root 运行${R}" && exit 1

YW_CFG="/etc/haproxy/haproxy-yw.cfg"
MAIN_CFG="/etc/haproxy/haproxy.cfg"
SYSCTL_CFG="/etc/sysctl.d/99-yw-transit.conf"

get_my_ip() {
    local ip
    ip=$(curl -4 -s --connect-timeout 3 https://ifconfig.me 2>/dev/null || \
         curl -4 -s --connect-timeout 3 https://checkip.amazonaws.com 2>/dev/null || \
         curl -4 -s --connect-timeout 3 https://api.ipify.org 2>/dev/null)
    echo "${ip:-未知IP}"
}

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

# ==========================================
# 核心底层：生产级环境初始化引擎
# ==========================================
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

    # 2. 现代化 Sysctl 配置 (防冲突)
    if [ ! -f "$SYSCTL_CFG" ] || ! grep -q "net.ipv4.ip_forward" "$SYSCTL_CFG" 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" > "$SYSCTL_CFG"
        sysctl -p "$SYSCTL_CFG" > /dev/null 2>&1
    fi

    # 3. 跨国大包防坑：MSS 钳制
    if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    fi

    # 4. 【防穿透补丁】放行 FORWARD 链 (UDP游戏转发的生命线)
    if ! iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi
    # 允许我们的中转机主动发起的转发包出去
    if ! iptables -C FORWARD -i lo -j ACCEPT 2>/dev/null; then
        iptables -I FORWARD -i lo -j ACCEPT
    fi

    # 5. 动态性能算法
    local mem_mb=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
    local safe_maxconn=1500
    local safe_maxfd=65535

    if [ "$mem_mb" -ge 64000 ]; then
        safe_maxconn=120000; safe_maxfd=200000
    elif [ "$mem_mb" -ge 32000 ]; then
        safe_maxconn=80000; safe_maxfd=150000
    elif [ "$mem_mb" -ge 16000 ]; then
        safe_maxconn=50000; safe_maxfd=100000
    elif [ "$mem_mb" -ge 8000 ]; then
        safe_maxconn=30000; safe_maxfd=65000
    elif [ "$mem_mb" -ge 4000 ]; then
        safe_maxconn=15000; safe_maxfd=50000
    elif [ "$mem_mb" -ge 2000 ]; then
        safe_maxconn=5000; safe_maxfd=32768
    fi

    # 6. 【OS级授权补丁】解除 Linux 对 HAProxy 的文件描述符封锁
    if ! grep -q "haproxy.*nofile.*${safe_maxfd}" /etc/security/limits.conf 2>/dev/null; then
        sed -i '/^haproxy.*nofile/d' /etc/security/limits.conf 2>/dev/null
        echo -e "haproxy soft nofile ${safe_maxfd}\nhaproxy hard nofile ${safe_maxfd}" >> /etc/security/limits.conf
        # 让当前 session 也立刻生效（无需重启）
        ulimit -n $safe_maxfd 2>/dev/null
    fi

    # 7. 检测是否需要重建主配置
    local need_rebuild=0
    if ! grep -q "YW Ultimate Safe Core" "$MAIN_CFG" 2>/dev/null; then
        need_rebuild=1
    elif ! grep -q "maxconn ${safe_maxconn}" "$MAIN_CFG" 2>/dev/null; then
        need_rebuild=1
    fi

    if [ "$need_rebuild" -eq 1 ]; then
        echo -e "${Y}正在部署 HAProxy 生产级核心...${R}"
        echo -e "${H}  ├─ 检测内存: ${mem_mb} MB${R}"
        echo -e "${H}  ├─ 并发上限: ${safe_maxconn}${R}"
        echo -e "${H}  └─ OS级文件锁: ${safe_maxfd}${R}"
        
        [ -f "$MAIN_CFG" ] && cp "$MAIN_CFG" "${MAIN_CFG}.bak.$(date +%s)"
        
        cat > "$MAIN_CFG" << MAIN_EOF
# ==========================================
# YW Ultimate Safe Core (生产级全自适应版)
# 动态生成于: $(date '+%Y-%m-%d %H:%M:%S')
# ==========================================
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn ${safe_maxconn}
    maxfd ${safe_maxfd}

defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    timeout connect 5s
    timeout client 5m
    timeout server 5m
    timeout check 2s

# YW 面板动态配置区 (严禁删除此行)
\$INCLUDE /etc/haproxy/haproxy-yw.cfg
MAIN_EOF
    fi

    if [ ! -f "$YW_CFG" ]; then
        cat > "$YW_CFG" << 'EOF'
# ==========================================
# YW 面板自动生成的 HAProxy 配置
# ==========================================
EOF
    fi

    systemctl enable haproxy > /dev/null 2>&1
    save_rules
    reload_haproxy
}

reload_haproxy() {
    if haproxy -c -f "$MAIN_CFG" > /dev/null 2>&1; then
        systemctl reload haproxy > /dev/null 2>&1
        return 0
    else
        echo -e "${RED}HAProxy 配置语法错误，拒绝重载！${R}"
        return 1
    fi
}

# 端口合法性严格校验函数
check_port() {
    local port=$1
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}端口错误！必须是 1-65535 之间的数字。${R}"; return 1
    fi
    return 0
}

# ==========================================
# 引擎 1：添加 HAProxy (TCP/直播) 规则
# ==========================================
add_haproxy() {
    echo -e "${P}--- 添加 TCP/直播转发 (HAProxy 稳定引擎) ---${R}"
    
    read -e -p "请输入落地机真实 IP: " BACKEND_IP
    [[ ! "$BACKEND_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo -e "${RED}IP 格式错误！${R}" && return

    read -e -p "请输入落地机端口: " BACKEND_PORT
    check_port "$BACKEND_PORT" || return

    read -e -p "请输入中转机监听端口: " FRONTEND_PORT
    check_port "$FRONTEND_PORT" || return

    if iptables -t nat -C PREROUTING -p tcp --dport "$FRONTEND_PORT" -j DNAT 2>/dev/null; then
        echo -e "${RED}冲突！端口 $FRONTEND_PORT 已被 iptables TCP 规则占用。${R}"; return
    fi
    if grep -q "bind \*:${FRONTEND_PORT}" "$YW_CFG" 2>/dev/null; then
        echo -e "${Y}HAProxy 中端口 $FRONTEND_PORT 已存在。${R}"; return
    fi

    iptables -t raw -A PREROUTING -p tcp --dport "$FRONTEND_PORT" -j NOTRACK

    cat >> "$YW_CFG" << EOF

# YW_RULE_START_${FRONTEND_PORT}
frontend fe_${FRONTEND_PORT}
    bind *:${FRONTEND_PORT}
    timeout client 2h
    default_backend be_${FRONTEND_PORT}

backend be_${FRONTEND_PORT}
    timeout server 2h
    balance roundrobin
    option tcp-check
    tcp-check connect
    server svr_${FRONTEND_PORT} ${BACKEND_IP}:${BACKEND_PORT} check inter 5s fall 3 rise 2
# YW_RULE_END_${FRONTEND_PORT}
EOF

    if reload_haproxy; then
        save_rules
        echo -e "${G}✅ 添加成功：${C}$(get_my_ip):${FRONTEND_PORT} -> ${BACKEND_IP}:${BACKEND_PORT} [HAProxy/TCP/NOTRACK]${R}"
    else
        echo -e "${RED}配置写入失败，正在回滚...${R}"
        iptables -t raw -D PREROUTING -p tcp --dport "$FRONTEND_PORT" -j NOTRACK 2>/dev/null
        sed -i "/# YW_RULE_START_${FRONTEND_PORT}/,/# YW_RULE_END_${FRONTEND_PORT}/d" "$YW_CFG"
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
    check_port "$BACKEND_PORT" || return

    read -e -p "请输入中转机监听端口: " FRONTEND_PORT
    check_port "$FRONTEND_PORT" || return

    if grep -q "bind \*:${FRONTEND_PORT}" "$YW_CFG" 2>/dev/null; then
        echo -e "${RED}冲突！端口 $FRONTEND_PORT 已被 HAProxy 占用。${R}"; return
    fi

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

    while IFS= read -r port; do
        if [[ -n "$port" ]]; then
            dest=$(grep -A5 "frontend fe_${port}" "$YW_CFG" | grep "server svr" | awk '{print $3}')
            rules+=("$port -> ${dest%%:*}")
            rule_types+=("haproxy")
        fi
    done < <(grep "YW_RULE_START" "$YW_CFG" | awk -F'_' '{print $NF}')

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
        iptables -t raw -D PREROUTING -p tcp --dport "$del_port" -j NOTRACK 2>/dev/null
        sed -i "/# YW_RULE_START_${del_port}/,/# YW_RULE_END_${del_port}/d" "$YW_CFG"
        reload_haproxy
        save_rules
        echo -e "${G}✅ 已删除 HAProxy 端口 ${del_port} 的规则。${R}"
    else
        dest_full=$(iptables-save -t nat | awk -v p="$del_port" '/PREROUTING/ && /DNAT/ && /-p udp/ && $0 ~ ("--dport "p) {for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}')
        iptables -t nat -D PREROUTING -p udp --dport "$del_port" -j DNAT --to-destination "$dest_full" 2>/dev/null
        
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

    while IFS= read -r port; do
        if [[ -n "$port" ]]; then
            dest=$(grep -A5 "frontend fe_${port}" "$YW_CFG" | grep "server svr" | awk '{print $3}')
            echo -e "${G}[$idx]${R} [${P}HAProxy/TCP${R}] ${C}${my_ip}:${port}${R} -> ${B}${dest}${R}"
            has_rules=1; ((idx++))
        fi
    done < <(grep "YW_RULE_START" "$YW_CFG" | awk -F'_' '{print $NF}')

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
    echo -e "${G}    YW 生产级全场景中转面板 (T0)       "
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
