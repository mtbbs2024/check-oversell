#!/bin/bash
# ============================================================
#  KVM 宿主机超售检测脚本 (Host Overselling Detection)
#  从虚拟机内部检测 KVM 宿主机是否过度超售
#  作者: Claude
#  版本: 2.0 — KVM 宿主机专项
# ============================================================
#  原理说明:
#    在 KVM 环境中，虚拟机能看到宿主机暴露的某些信息
#    (CPUID leaves, L3 Cache, CPU 型号, DMI 信息等)。
#    通过综合分析这些信息与自身性能表现，可以推断
#    宿主机是否存在超售。
# ============================================================

set -e

# ---------- 颜色定义 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- 全局变量 ----------
RISK_SCORE=0
MAX_SCORE=0
REPORT_LINES=()
VIRT_TYPE="unknown"
IS_KVM=false

# CPU 相关
VCPU_COUNT=0
CPU_MODEL=""
CPU_SOCKETS=0
CPU_CORES_PER_SOCKET=0
CPU_THREADS_PER_CORE=0
L3_CACHE_SIZE=""

# KVM 相关
KVM_VERSION=""
QEMU_VERSION=""
BALLOON_ACTIVE=false

# ---------- 辅助函数 ----------
info()    { echo -e "${CYAN}[信息]${NC} $1"; }
good()    { echo -e "${GREEN}[通过]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
bad()     { echo -e "${RED}[异常]${NC} $1"; }
header()  { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }
detail()  { echo -e "  ${NC}  $1"; }
label()   { printf "  %-30s %s\n" "$1" "$2"; }

add_risk() { local w=$1 d=$2; RISK_SCORE=$((RISK_SCORE + w)); REPORT_LINES+=("+${w}:${d}"); }
add_max()  { MAX_SCORE=$((MAX_SCORE + $1)); }

# ---------- 检查 root ----------
if [[ $EUID -ne 0 ]]; then
    warn "部分检测需要 root 权限，建议以 root 运行以获得完整结果"
    echo ""
fi

echo -e ""
echo -e "${MAGENTA}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║     KVM 宿主机超售检测脚本 v2.0              ║${NC}"
echo -e "${MAGENTA}║     从虚拟机内部检测宿主机超售状态           ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════╝${NC}"
echo -e ""

# ============================================================
#  1. 验证虚拟化环境
# ============================================================
header "【第一步】验证虚拟化环境"

# 检测虚拟化类型
if command -v systemd-detect-virt &>/dev/null; then
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    if grep -qi "kvm\|qemu" /proc/cpuinfo 2>/dev/null || [[ "$VIRT_TYPE" == "kvm" ]]; then
        IS_KVM=true
    fi
fi

# 补充检测: CPUID KVM 签名
if grep -qi "KVM\|QEMU" /proc/cpuinfo 2>/dev/null; then
    IS_KVM=true
fi

# 检查 /sys 中的 hypervisor 信息
if [[ -d /sys/hypervisor ]] && [[ -f /sys/hypervisor/type ]]; then
    HVTYPE=$(cat /sys/hypervisor/type 2>/dev/null)
    [[ "$HVTYPE" == "kvm" ]] && IS_KVM=true
fi

if ! $IS_KVM; then
    bad "未检测到 KVM 虚拟化环境！当前虚拟化类型: ${VIRT_TYPE}"
    bad "此脚本专为 KVM 环境设计，其他虚拟化环境检测可能不准确"
    echo -e ""
    echo -e "${YELLOW}仍在继续执行，但部分检测项可能不适用...${NC}"
else
    good "确认运行在 KVM 虚拟化环境中 (${VIRT_TYPE})"
fi
add_max 5

# ============================================================
#  2. 宿主机 CPU 型号识别与分析
# ============================================================
header "【第二步】宿主机 CPU 型号识别与分析"

CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | sed 's/.*:\s*//')
VCPU_COUNT=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
THREADS_PER_CORE=$(lscpu 2>/dev/null | grep "Thread(s) per core" | awk '{print $NF}')
CORES_PER_SOCKET=$(lscpu 2>/dev/null | grep "Core(s) per socket" | awk '{print $NF}')
SOCKETS=$(lscpu 2>/dev/null | grep "Socket(s)" | awk '{print $NF}')
NUMA_NODES=$(lscpu 2>/dev/null | grep "NUMA node(s)" | awk '{print $NF}')

# 处理一些空值情况
[[ -z "$THREADS_PER_CORE" ]] && THREADS_PER_CORE=1
[[ -z "$CORES_PER_SOCKET" ]] && CORES_PER_SOCKET=$VCPU_COUNT
[[ -z "$SOCKETS" ]] && SOCKETS=1
[[ -z "$NUMA_NODES" ]] && NUMA_NODES=1

label "CPU 型号:"         "${CPU_MODEL:-未知}"
label "vCPU 总数:"        "${VCPU_COUNT}"
label "每 Socket 核心数:" "${CORES_PER_SOCKET}"
label "每核心线程数:"     "${THREADS_PER_CORE}"
label "Socket 数:"        "${SOCKETS}"
label "NUMA 节点数:"      "${NUMA_NODES}"

# ----- 2.1 CPU 模式检测 -----
echo ""
info "检查 CPU 透传模式..."

if echo "$CPU_MODEL" | grep -qi "QEMU Virtual"; then
    echo -e "  ⚡ CPU 模式: ${YELLOW}QEMU 通用模拟${NC}"
    echo -e "  ${NC}  宿主机使用了 QEMU 通用 CPU 模型（非透传/non-passthrough）"
    echo -e "  ${NC}  说明宿主机在 CPU 型号上做了隐藏，无法直接识别物理 CPU"
    add_risk 1 "QEMU 通用 CPU 模型，无法直接识别宿主 CPU"

    # 虽然有隐藏，但还可以通过其他方式判定超售
    # 尝试从 lscpu 获取更多信息
    CPU_FAMILY=$(lscpu 2>/dev/null | grep "^CPU family:" | awk '{print $NF}')
    CPU_MODEL_NUM=$(lscpu 2>/dev/null | grep "^Model:" | awk '{print $NF}')
    label "CPU Family:"    "${CPU_FAMILY:-未知}"
    label "CPU Model#:"    "${CPU_MODEL_NUM:-未知}"

elif echo "$CPU_MODEL" | grep -qi "Common KVM"; then
    echo -e "  ⚡ CPU 模式: ${YELLOW}Common KVM (Red Hat 通用模型)${NC}"

elif echo "$CPU_MODEL" | grep -qi "Intel\|AMD\|Hygon\|EPYC\|Xeon"; then
    echo -e "  ⚡ CPU 模式: ${GREEN}物理 CPU 透传 (host-passthrough/host-model)${NC}"
    echo -e "  ${NC}  宿主机暴露了物理 CPU 型号，可以更准确地分析"
    good "可以执行物理 CPU 规格对比分析"
else
    echo -e "  ⚡ CPU 模式: ${YELLOW}未知/其它${NC}"
fi
add_max 3

# ----- 2.2 CPU 物理规格对比 (内置常见服务器 CPU 数据库) -----
echo ""
info "CPU 物理规格对比分析..."

# 内置常见 CPU 规格: [型号]=物理核心数:基础频率GHz:全核睿频:单核睿频:L3缓存MB
declare -A CPU_DB
# Intel Xeon Scalable (一代)
CPU_DB["Platinum 8176"]="28:2.10:3.20:3.80:38.5"
CPU_DB["Platinum 8168"]="24:2.70:3.40:3.70:33.0"
CPU_DB["Gold 6148"]="20:2.40:3.20:3.70:27.5"
CPU_DB["Gold 6142"]="16:2.60:3.30:3.70:22.0"
CPU_DB["Gold 6130"]="16:2.10:2.80:3.70:22.0"
CPU_DB["Silver 4116"]="12:2.10:2.60:3.00:16.5"
CPU_DB["Silver 4110"]="8:2.10:2.60:3.00:11.0"
CPU_DB["Bronze 3106"]="8:1.70:1.80:1.80:11.0"

# Intel Xeon Scalable (二代)
CPU_DB["Platinum 8280"]="28:2.70:3.40:4.00:38.5"
CPU_DB["Platinum 8276"]="28:2.20:3.20:3.80:38.5"
CPU_DB["Gold 6248"]="20:2.50:3.30:3.90:27.5"
CPU_DB["Gold 6230"]="20:2.10:2.80:3.90:27.5"
CPU_DB["Silver 4214"]="12:2.20:2.70:3.20:16.5"

# Intel Xeon Scalable (三代) — Ice Lake
CPU_DB["Platinum 8380"]="40:2.30:3.20:3.40:60.0"
CPU_DB["Platinum 8368"]="38:2.40:3.20:3.40:57.0"
CPU_DB["Platinum 8358"]="32:2.60:3.20:3.40:48.0"
CPU_DB["Gold 6348"]="28:2.60:3.20:3.50:42.0"
CPU_DB["Gold 6338"]="28:2.00:2.80:3.20:42.0"
CPU_DB["Silver 4314"]="16:2.40:2.70:3.40:24.0"

# Intel Xeon Scalable (四代) — Sapphire Rapids
CPU_DB["Platinum 8480+"]="56:2.00:3.00:3.80:105.0"
CPU_DB["Platinum 8468"]="48:2.10:3.10:3.80:105.0"
CPU_DB["Platinum 8458"]="32:2.70:3.30:3.80:97.0"
CPU_DB["Gold 6448"]="32:2.10:2.80:3.80:60.0"

# Intel Xeon E-系列
CPU_DB["E-2388G"]="8:3.20:5.10:5.10:16.0"
CPU_DB["E-2288G"]="8:3.70:4.90:5.00:16.0"
CPU_DB["E-2278G"]="8:3.40:4.80:5.00:16.0"

# Intel Core (低端 VPS 常见)
CPU_DB["i9-13900K"]="24:3.00:5.40:5.80:36.0"
CPU_DB["i9-12900K"]="16:3.20:5.00:5.20:30.0"
CPU_DB["i7-12700"]="12:2.10:4.80:4.90:25.0"
CPU_DB["i5-12400"]="6:2.50:4.40:4.40:18.0"

# AMD EPYC (一代)
CPU_DB["EPYC 7601"]="32:2.20:2.70:3.20:64.0"
CPU_DB["EPYC 7551"]="32:2.00:2.55:3.00:64.0"
CPU_DB["EPYC 7401"]="24:2.00:2.80:3.00:64.0"

# AMD EPYC (二代 — Rome)
CPU_DB["EPYC 7H12"]="64:2.60:3.30:3.30:256.0"
CPU_DB["EPYC 7702"]="64:2.00:3.00:3.35:256.0"
CPU_DB["EPYC 7642"]="48:2.40:3.00:3.30:256.0"
CPU_DB["EPYC 7502"]="32:2.50:3.00:3.35:128.0"
CPU_DB["EPYC 7402"]="24:2.80:3.00:3.35:128.0"
CPU_DB["EPYC 7302"]="16:3.00:3.00:3.30:128.0"

# AMD EPYC (三代 — Milan)
CPU_DB["EPYC 7763"]="64:2.45:3.20:3.50:256.0"
CPU_DB["EPYC 7713"]="64:2.00:3.20:3.68:256.0"
CPU_DB["EPYC 7543"]="32:2.80:3.20:3.70:256.0"
CPU_DB["EPYC 7443"]="24:2.85:3.20:3.70:128.0"
CPU_DB["EPYC 7343"]="16:3.20:3.40:3.70:128.0"

# AMD EPYC (四代 — Genoa)
CPU_DB["EPYC 9654"]="96:2.40:3.55:3.70:384.0"
CPU_DB["EPYC 9554"]="64:3.75:3.75:3.75:256.0"
CPU_DB["EPYC 9454"]="48:2.75:3.45:3.80:256.0"
CPU_DB["EPYC 9354"]="32:3.25:3.55:3.80:256.0"

MATCHED_CPU=""
MAX_PHYSICAL_CORES=0
MAX_L3_MB=0
BASE_GHZ=""
TURBO_GHZ=""

# 尝试匹配 CPU 型号
for key in "${!CPU_DB[@]}"; do
    if echo "$CPU_MODEL" | grep -qi "$key"; then
        MATCHED_CPU="$key"
        IFS=':' read -r cores base_ghz allcore_turbo single_turbo l3 <<< "${CPU_DB[$key]}"
        MAX_PHYSICAL_CORES=$cores
        MAX_L3_MB=$(echo "$l3" | awk '{printf "%.0f", $1}')
        BASE_GHZ=$base_ghz
        TURBO_GHZ=$single_turbo
        break
    fi
done

if [[ -n "$MATCHED_CPU" ]]; then
    good "匹配到物理 CPU: ${MATCHED_CPU}"
    label "物理核心数:"   "${MAX_PHYSICAL_CORES} 核心"
    label "基础频率:"     "${BASE_GHZ} GHz"
    label "单核睿频:"     "${TURBO_GHZ} GHz"
    label "L3 缓存:"      "${MAX_L3_MB} MB"

    # vCPU 与物理核心数对比
    if [[ "$MAX_PHYSICAL_CORES" -gt 0 ]]; then
        echo ""
        if [[ "$VCPU_COUNT" -le "$MAX_PHYSICAL_CORES" ]]; then
            # 如果开了超线程，物理核心*2才是最大 vCPU 数
            MAX_VCPU_WITH_HT=$((MAX_PHYSICAL_CORES * 2))
            if [[ "$VCPU_COUNT" -le "$MAX_VCPU_WITH_HT" ]]; then
                good "vCPU 数(${VCPU_COUNT}) ≤ 物理核心×2(${MAX_VCPU_WITH_HT})，数量在合理范围内"
            else
                warn "vCPU 数(${VCPU_COUNT}) 超过物理核心×2(${MAX_VCPU_WITH_HT})，存在 CPU 超售!"
                RATIO=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / $MAX_VCPU_WITH_HT}")
                warn "vCPU:物理线程 = ${VCPU_COUNT}:${MAX_VCPU_WITH_HT} = ${RATIO}x"
                add_risk 6 "vCPU(${VCPU_COUNT}) 超过物理线程(${MAX_VCPU_WITH_HT})，比率 ${RATIO}x"
            fi
        else
            warn "vCPU 数(${VCPU_COUNT}) 超过物理核心数(${MAX_PHYSICAL_CORES})，确实存在 CPU 超售!"
            RATIO=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / $MAX_PHYSICAL_CORES}")
            warn "vCPU:物理核心 = ${VCPU_COUNT}:${MAX_PHYSICAL_CORES} = ${RATIO}x"
            add_risk 6 "vCPU(${VCPU_COUNT}) 超过物理核心(${MAX_PHYSICAL_CORES})，比率 ${RATIO}x"
        fi
    fi
else
    info "CPU 型号不在内置数据库中，将使用其他方法估算"
    add_risk 1 "CPU 不在已知数据库中，对比受限"
fi
add_max 6

# ----- 2.3 L3 Cache 分析 (核心的宿主机核心数估算方法) -----
echo ""
info "L3 Cache 分析（估算宿主机物理核心数）..."

# 读取 L3 cache 大小
for cache_idx in /sys/devices/system/cpu/cpu0/cache/index*/; do
    if [[ -f "${cache_idx}type" ]]; then
        CTYPE=$(cat "${cache_idx}type" 2>/dev/null)
        if [[ "$CTYPE" == "Unified" ]]; then
            L3_CACHE_SIZE=$(cat "${cache_idx}size" 2>/dev/null)
            break
        fi
    fi
done

# 备用: 用 dmesg 信息
if [[ -z "$L3_CACHE_SIZE" ]]; then
    L3_CACHE_SIZE=$(dmesg 2>/dev/null | grep -i "cache\|L3" | grep -oP '\d+K.*L3' | head -1 || echo "")
fi

# 再用 lscpu 备用
if [[ -z "$L3_CACHE_SIZE" ]]; then
    L3_CACHE_SIZE=$(lscpu 2>/dev/null | grep "L3" | awk '{print $NF}')
fi

if [[ -n "$L3_CACHE_SIZE" ]]; then
    # 统一单位到 MB
    L3_NUM=0
    if echo "$L3_CACHE_SIZE" | grep -qi "M"; then
        L3_NUM=$(echo "$L3_CACHE_SIZE" | grep -oP '[\d.]+' | head -1)
    elif echo "$L3_CACHE_SIZE" | grep -qi "K"; then
        L3_VAL=$(echo "$L3_CACHE_SIZE" | grep -oP '[\d.]+' | head -1)
        L3_NUM=$(awk "BEGIN {printf \"%.1f\", $L3_VAL / 1024}")
    else
        L3_NUM=$(echo "$L3_CACHE_SIZE" | grep -oP '[\d.]+' | head -1)
    fi

    label "L3 Cache 大小:" "${L3_NUM} MB"

    if [[ -n "$MAX_L3_MB" ]] && [[ "$MAX_L3_MB" -gt 0 ]]; then
        # 对比已知 CPU 的 L3 大小
        label "预期 L3 大小:"   "${MAX_L3_MB} MB (${MATCHED_CPU})"

        # 估算宿主机物理核心数: L3全量 / (L3每核)
        # 常见架构: Intel Xeon 每核约 1.375-1.5MB L3, AMD EPYC 每 CCD 32MB
        # Intel Xeon: L3 通常每核心 1.375MB (比如 28核38.5MB)
        # AMD EPYC: 每8核心一组 CCX 共享 L3 (32MB 一组)
        if echo "$CPU_MODEL" | grep -qi "Intel"; then
            L3_PER_CORE="1.375"
            ESTIMATED_HOST_CORES=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / $L3_PER_CORE}")
            info "Intel 架构 → 估算每核 L3 约 ${L3_PER_CORE}MB"
            label "估算宿主机物理核心:" "${ESTIMATED_HOST_CORES} 核"
            label "你的 vCPU:"          "${VCPU_COUNT} vCPU"

            if [[ "$VCPU_COUNT" -gt 0 ]] && [[ "$ESTIMATED_HOST_CORES" -gt 0 ]] && [[ "$ESTIMATED_HOST_CORES" -ge "$VCPU_COUNT" ]]; then
                # 估算超售比
                HOST_CORE_RATIO=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / $ESTIMATED_HOST_CORES}")
                label "vCPU占用宿主机比例:" "${HOST_CORE_RATIO}x"
                if (( $(echo "$HOST_CORE_RATIO > 2.0" | bc -l 2>/dev/null || echo 0) )); then
                    bad "从 L3 分析，vCPU 数远大于估算宿主机核心数，超售严重！"
                    add_risk 5 "L3分析: vCPU/核心=${HOST_CORE_RATIO}x，严重超售"
                elif (( $(echo "$HOST_CORE_RATIO > 1.0" | bc -l 2>/dev/null || echo 0) )); then
                    warn "L3 分析显示 vCPU 数超过估算宿主机核心数"
                    add_risk 3 "L3分析: vCPU/核心=${HOST_CORE_RATIO}x"
                else
                    good "L3 分析显示 vCPU 数在合理范围内"
                fi
            elif [[ "$VCPU_COUNT" -gt 0 ]] && [[ "$ESTIMATED_HOST_CORES" -gt 0 ]] && [[ "$ESTIMATED_HOST_CORES" -lt "$VCPU_COUNT" ]]; then
                bad "vCPU(${VCPU_COUNT}) > 估算宿主机核心(${ESTIMATED_HOST_CORES})，存在 CPU 超售！"
                add_risk 5 "L3分析: vCPU(${VCPU_COUNT}) > 估算核心(${ESTIMATED_HOST_CORES})"
            fi
        elif echo "$CPU_MODEL" | grep -qi "AMD"; then
            # AMD EPYC L3 分组: 每 8 核共享 32MB (Genoa 之前)
            ESTIMATED_CCD=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 32}")
            ESTIMATED_HOST_CORES=$((ESTIMATED_CCD * 8))
            info "AMD 架构 → 估算每 CCD 32MB L3"
            label "估算 CCD 数量:"    "${ESTIMATED_CCD}"
            label "估算宿主机物理核心:" "${ESTIMATED_HOST_CORES} 核"
            label "你的 vCPU:"          "${VCPU_COUNT} vCPU"

            if [[ "$ESTIMATED_CCD" -ge 1 ]]; then
                if [[ "$VCPU_COUNT" -gt "$ESTIMATED_HOST_CORES" ]]; then
                    bad "vCPU 数(${VCPU_COUNT}) 超过估算核心(${ESTIMATED_HOST_CORES})，CPU 超售！"
                    add_risk 5 "L3(AMD)分析: vCPU超过估算核心"
                fi
            fi
        fi
        add_max 5
    else
        # 没有识别到具体 CPU 型号，但可以用 L3 大致估算
        info "未知 CPU 型号，仅用 L3 缓存大小做粗略估算"

        # 大 L3 + 少 vCPU = 宿主有很多核心但只分了你一点 → 不一定超售，也可能是少核套餐
        # 小 L3 + 多 vCPU = 宿主核心少但分了很多 vCPU → 可能是超售
        # 但需要参考架构，这里仅做个提示
        if [[ -n "$L3_NUM" ]]; then
            L3_PER_VCPU=$(awk "BEGIN {printf \"%.1f\", $L3_NUM / $VCPU_COUNT}" 2>/dev/null)
            label "L3/vCPU 比值:" "${L3_PER_VCPU} MB/vCPU"

            if (( $(echo "$L3_PER_VCPU > 10.0" | bc -l 2>/dev/null || echo 0) )); then
                warn "每个 vCPU 对应 L3 异常大(${L3_PER_VCPU}MB)，宿主可能将 L3 共享给多个 VM"
                add_risk 2 "L3/vCPU=${L3_PER_VCPU}MB，可能缓存共享"
            fi
        fi
    fi
else
    warn "无法检测 L3 缓存大小"
    add_risk 2 "无法检测 L3 Cache"
fi
add_max 3

# ============================================================
#  3. CPU Steal Time 深度检测 (超售最核心指标)
# ============================================================
header "【第三步】CPU Steal Time 深度检测"

add_max 15

STEAL_AVAILABLE=false
if [[ -f /proc/stat ]]; then
    COLUMNS=$(awk '/^cpu / {print NF-1}' /proc/stat 2>/dev/null)
    [[ "$COLUMNS" -ge 8 ]] && STEAL_AVAILABLE=true
fi

do_steal_test() {
    local duration=$1
    local label=$2
    local load_cmd=$3

    local S1 T1 S2 T2

    if [[ -n "$load_cmd" ]]; then
        # 在后台运行负载
        eval "$load_cmd" &
        local load_pid=$!
        # 等待负载启动
        sleep 1
    fi

    read S1 T1 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)
    sleep "$duration"
    read S2 T2 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)

    [[ -n "$load_pid" ]] && kill "$load_pid" 2>/dev/null || true

    if [[ -n "$S1" && -n "$S2" && -n "$T1" && -n "$T2" ]]; then
        local s_delta=$((S2 - S1))
        local t_delta=$((T2 - T1))
        if [[ "$t_delta" -gt 0 ]]; then
            awk "BEGIN {printf \"%.2f\", ($s_delta / $t_delta) * 100}"
        else
            echo "0"
        fi
    else
        echo "-1"
    fi
}

if $STEAL_AVAILABLE; then
    info "KVM Steal Time 采样分析（这是判断超售最核心的指标）"

    # 3.1 空闲状态的 Steal Time
    echo ""
    info "测试 1/4: 空闲状态 Steal Time (3 次采样取平均)..."
    TOTAL_STEAL_IDLE=0
    SAMPLES=3
    for i in $(seq 1 $SAMPLES); do
        RES=$(do_steal_test 2 "idle_$i" "")
        if [[ "$RES" != "-1" ]] && [[ "$RES" != "0" ]]; then
            detail "  第 ${i} 次: ${RES}%"
            TOTAL_STEAL_IDLE=$(awk "BEGIN {printf \"%.2f\", $TOTAL_STEAL_IDLE + $RES}")
        fi
    done
    AVG_IDLE=$(awk "BEGIN {printf \"%.2f\", $TOTAL_STEAL_IDLE / $SAMPLES}" 2>/dev/null || echo "0")

    label "空闲时平均 Steal:" "${AVG_IDLE}%"

    # 3.2 CPU 轻负载下的 Steal Time (单线程)
    echo ""
    info "测试 2/4: 单线程负载下 Steal Time..."
    LOAD_CMD='i=0; while [ $i -lt 100000000 ]; do i=$((i+1)); done &>/dev/null'
    if command -v sha256sum &>/dev/null; then
        LOAD_CMD='sha256sum /dev/zero &>/dev/null &
sleep 2
while kill -0 $! 2>/dev/null; do sha256sum /dev/zero &>/dev/null; done'
    fi

    RES_LOAD=$(do_steal_test 3 "load" "sha256sum /dev/zero &>/dev/null & sleep 3")
    if [[ "$RES_LOAD" == "-1" ]]; then
        RES_LOAD=0
    fi

    label "负载时 Steal:" "${RES_LOAD}%"

    # 3.3 全 CPU 满载下的 Steal Time
    echo ""
    info "测试 3/4: 全 vCPU 满负载 Steal Time (${VCPU_COUNT} 线程并发)..."
    # 启动 n 个 sha256sum 进程，数量等于 vCPU
    PIDS=""
    for ((i=0; i<VCPU_COUNT; i++)); do
        sha256sum /dev/zero &>/dev/null &
        PIDS="$PIDS $!"
    done
    sleep 1

    read S1 T1 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)
    sleep 4
    read S2 T2 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)

    # 清理后台进程
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done 2>/dev/null

    s_delta=$((S2 - S1))
    t_delta=$((T2 - T1))
    if [[ "$t_delta" -gt 0 ]]; then
        FULL_LOAD_STEAL=$(awk "BEGIN {printf \"%.2f\", ($s_delta / $t_delta) * 100}")
    else
        FULL_LOAD_STEAL=0
    fi
    label "满载时 Steal:"   "${FULL_LOAD_STEAL}%"

    # 3.4 Steal 波动检测 (判断是否间歇性争抢)
    echo ""
    info "测试 4/4: Steal Time 波动检测（5秒内快速采样）..."
    for i in $(seq 1 5); do
        R=$(do_steal_test 3 "quick_$i" "")
        if [[ "$R" == "-1" ]]; then R=0; fi
        STEAL_SAMPLES[$i]=$R
    done
    MAX_STEAL=0
    MIN_STEAL=100
    for s in "${STEAL_SAMPLES[@]}"; do
        if (( $(echo "$s > $MAX_STEAL" | bc -l 2>/dev/null) )); then MAX_STEAL=$s; fi
        if (( $(echo "$s < $MIN_STEAL" | bc -l 2>/dev/null) )); then MIN_STEAL=$s; fi
    done
    STEAL_JITTER=$(awk "BEGIN {printf \"%.2f\", $MAX_STEAL - $MIN_STEAL}" 2>/dev/null || echo "0")
    label "Steal 波动范围:"   "${MIN_STEAL}% ~ ${MAX_STEAL}%"
    label "Steal 抖动幅度:"   "${STEAL_JITTER}%"

    # ----- 综合评分 -----
    echo ""
    info "CPU Steal Time 综合判定..."

    # 使用最大值进行判断 (峰值最能反映超售)
    WORST_STEAL=$AVG_IDLE
    if (( $(echo "$RES_LOAD > $WORST_STEAL" | bc -l 2>/dev/null) )); then WORST_STEAL=$RES_LOAD; fi
    if (( $(echo "$FULL_LOAD_STEAL > $WORST_STEAL" | bc -l 2>/dev/null) )); then WORST_STEAL=$FULL_LOAD_STEAL; fi

    label "最差 Steal:"     "${WORST_STEAL}%"

    if (( $(echo "$WORST_STEAL > 30.0" | bc -l 2>/dev/null || echo 0) )); then
        bad "CPU Steal Time 极高(${WORST_STEAL}%)！宿主机严重超售！"
        bad "大量 vCPU 在等待物理 CPU 时间片，性能严重受损"
        add_risk 12 "Steal=${WORST_STEAL}%，严重超售"
    elif (( $(echo "$WORST_STEAL > 15.0" | bc -l 2>/dev/null || echo 0) )); then
        bad "CPU Steal Time 很高(${WORST_STEAL}%)，宿主机明显超售"
        add_risk 8 "Steal=${WORST_STEAL}%，明显超售"
    elif (( $(echo "$WORST_STEAL > 8.0" | bc -l 2>/dev/null || echo 0) )); then
        warn "CPU Steal Time 偏高(${WORST_STEAL}%)，宿主机存在超售"
        add_risk 5 "Steal=${WORST_STEAL}%，存在超售"
    elif (( $(echo "$WORST_STEAL > 3.0" | bc -l 2>/dev/null || echo 0) )); then
        warn "CPU Steal Time 略高(${WORST_STEAL}%)，可能有轻度争抢"
        add_risk 3 "Steal=${WORST_STEAL}%，轻度争抢"
    elif (( $(echo "$WORST_STEAL > 1.0" | bc -l 2>/dev/null || echo 0) )); then
        info "CPU Steal Time 正常(${WORST_STEAL}%)"
        add_risk 1 "Steal=${WORST_STEAL}%"
    else
        good "CPU Steal Time 极低(${WORST_STEAL}%)，几乎没有争抢"
    fi

    # Steal 波动大也是超售特征
    if (( $(echo "$STEAL_JITTER > 10.0" | bc -l 2>/dev/null || echo 0) )); then
        warn "Steal 波动极大(${STEAL_JITTER}%)，说明 CPU 争抢不稳定、间歇性严重"
        add_risk 3 "Steal 波动 ${STEAL_JITTER}%，间歇性争抢"
    fi

    # 空闲 vs 负载 Steal 差异大 → 宿主按需分配 CPU
    if (( $(echo "$RES_LOAD > $AVG_IDLE * 3" | bc -l 2>/dev/null || echo 0) )); then
        warn "加负载后 Steal 急剧上升，宿主按需分配 CPU，其他 VM 在抢资源"
        add_risk 2 "负载后 Steal 急剧上升，按需分配"
    fi
else
    warn "/proc/stat 中无 Steal 列，无法使用 Steal Time 检测"
    if [[ -f /proc/user_beancounters ]]; then
        info "OpenVZ 环境没有 Steal Time 概念"
    fi
    add_risk 10 "Steal Time 不可用，核心检测缺失"
fi

# ============================================================
#  4. KVM 特有检测项
# ============================================================
header "【第四步】KVM 特有检测项"

# 4.1 KVM CPUID 特征检测
echo ""
info "KVM CPUID 特征检测..."
KVM_CPUID_HINT=""
if command -v cpuid &>/dev/null; then
    KVM_SIG=$(cpuid -1 -l 0x40000000 2>/dev/null | grep -i "KVM" || echo "")
    if [[ -n "$KVM_SIG" ]]; then
        good "检测到 KVM CPUID 签名: KVMKVMKVM"
        # 尝试获取 KVM 版本
        KVM_FEATURES=$(cpuid -1 -l 0x40000001 2>/dev/null | head -5)
        if [[ -n "$KVM_FEATURES" ]]; then
            KVM_CPUID_HINT=$(echo "$KVM_FEATURES" | grep "eax" | awk -F'=' '{print $2}' | xargs)
            label "KVM 特征标志:" "${KVM_CPUID_HINT:-未知}"
        fi
    else
        info "cpuid 工具可用但未提取到 KVM 签名"
    fi
else
    info "未安装 cpuid 工具 (apt install cpuid / yum install cpuid)"
    info "安装后可获取更详细的 KVM 宿主机信息"
fi
add_max 2

# 4.2 检查 virtio_balloon
echo ""
info "检查 virtio_balloon (内存气球驱动 — KVM 内存超售标志)..."
if lsmod 2>/dev/null | grep -qi "virtio_balloon"; then
    BALLOON_ACTIVE=true
    warn "virtio_balloon 驱动已加载！宿主机可能在进行内存超售 (ballooning)"

    # 检查 dmesg 中是否有 balloon 活动记录
    if dmesg 2>/dev/null | grep -i "balloon" | head -5 | grep -qi "inflate\|deflate\|update\|report"; then
        warn "Balloon 驱动有活跃的充气/放气记录！"
        dmesg 2>/dev/null | grep -i "balloon" | tail -3 | while read -r line; do
            detail "  ${line}"
        done
        add_risk 6 "virtio_balloon 活跃，内存被超售"
    else
        warn "Balloon 驱动已加载，但未见活动记录"
        add_risk 4 "virtio_balloon 已加载，潜在内存超售"
    fi
else
    good "未加载 virtio_balloon 驱动，内存无 ballooning"
fi
add_max 6

# 4.3 检查 virtio 设备类型 (virtio = 半虚拟化, e1000/rtl8139 = 全模拟)
echo ""
info "检测 virtio 设备使用情况 (virtio = 高性能半虚拟化, 模拟设备 = 宿主机 CPU 开销大)..."
VIRTIO_DEVICES=""
EMULATED_DEVICES=""

if command -v lspci &>/dev/null; then
    for dev in $(lspci 2>/dev/null | awk '{print $1}'); do
        DEVINFO=$(lspci -s "$dev" -v 2>/dev/null | head -10)
        if echo "$DEVINFO" | grep -qi "VirtIO\|Red Hat.*Virtio"; then
            VIRTIO_DEVICES="$VIRTIO_DEVICES $dev"
        elif echo "$DEVINFO" | grep -qi "e1000\|rtl8139\|vmxnet"; then
            EMULATED_DEVICES="$EMULATED_DEVICES $dev"
        fi
    done
fi

# 也检查 /sys/bus
if [[ -d /sys/bus/virtio/devices ]]; then
    VIO_COUNT=$(ls /sys/bus/virtio/devices/ 2>/dev/null | wc -l)
    if [[ "$VIO_COUNT" -gt 0 ]]; then
        good "发现 ${VIO_COUNT} 个 virtio 设备 (半虚拟化，高性能)"
    fi
fi

if [[ -n "$EMULATED_DEVICES" ]]; then
    warn "检测到模拟设备 (${EMULATED_DEVICES})"
    warn "模拟设备增加宿主机 CPU 开销，说明宿主可能未优化 VCPU 分配"
    add_risk 2 "使用模拟设备(非 virtio)，增加宿主 CPU 开销"
fi

# 4.4 检测 DMI 信息 (可能暴露宿主机硬件信息)
echo ""
info "检测 DMI 信息（可能暴露宿主机硬件信息）..."

# Hyper-V  enlightenment 检测 (KVM 也有这些)
if [[ -d /sys/hypervisor ]]; then
    detail "存在 /sys/hypervisor 目录"
fi

# 检查是否开启了 KVM PV 功能
if [[ -f /sys/kernel/debug/kvm ]] || [[ -d /proc/sys/kernel ]]; then
    KVM_CLOCK=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo "")
    if [[ "$KVM_CLOCK" == "kvm-clock" ]]; then
        good "使用 KVM 半虚拟化时钟 (kvm-clock)，时间同步正常"
    fi
fi
add_max 2

# 4.5 QEMU 版本检测
echo ""
info "检测 QEMU 版本..."
# 通过 DMI product name 检测
if [[ -f /sys/class/dmi/id/product_name ]]; then
    DMI_PRODUCT=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    DMI_VERSION=$(cat /sys/class/dmi/id/product_version 2>/dev/null)
    if [[ -n "$DMI_PRODUCT" ]]; then
        label "DMI 产品名:" "${DMI_PRODUCT}"
        label "DMI 版本:"   "${DMI_VERSION:-未知}"
        if echo "$DMI_PRODUCT" | grep -qi "qemu\|KVM"; then
            QEMU_VERSION=$(echo "$DMI_PRODUCT" | grep -oP '[\d.]+' || echo "未知")
            label "QEMU 版本:" "${QEMU_VERSION:-未知}"

            # 旧版 QEMU 可能意味着宿主机缺乏优化
            if [[ -n "$QEMU_VERSION" ]]; then
                QEMU_MAJOR=$(echo "$QEMU_VERSION" | cut -d. -f1)
                if [[ -n "$QEMU_MAJOR" ]] && [[ "$QEMU_MAJOR" -le 2 ]]; then
                    warn "QEMU 版本较旧 (${QEMU_VERSION})，可能缺乏最新优化"
                fi
            fi
        fi
    fi
fi
add_max 2

# ============================================================
#  5. 内存超售检测
# ============================================================
header "【第五步】内存超售检测"

if [[ -f /proc/meminfo ]]; then
    MEM_TOTAL=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    MEM_AVAIL=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo)
    MEM_FREE=$(awk '/MemFree/ {printf "%.0f", $2/1024}' /proc/meminfo)
    SWAP_TOTAL=$(awk '/SwapTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    COMMIT_LIMIT=$(awk '/CommitLimit/ {printf "%.0f", $2/1024}' /proc/meminfo)
    COMMITTED_AS=$(awk '/Committed_AS/ {printf "%.0f", $2/1024}' /proc/meminfo)
    SWAP_USED=$(awk '/SwapTotal/{s=$2}/SwapFree/{f=$2} END{printf "%.0f", (s-f)/1024}' /proc/meminfo)
    HUGEPAGE_TOTAL=$(awk '/HugePages_Total/{print $2}' /proc/meminfo)

    label "总内存:"       "${MEM_TOTAL} MB"
    label "可用内存:"     "${MEM_AVAIL} MB"
    label "Swap 总量:"    "${SWAP_TOTAL} MB"
    label "Swap 使用:"    "${SWAP_USED} MB"
    label "HugePages:"    "${HUGEPAGE_TOTAL:-0}"

    add_max 8

    # 5.1 核心: CommitLimit vs Committed_AS
    echo ""
    info "核心检测: 承诺内存 (Committed_AS) vs 承诺限制 (CommitLimit)..."

    if [[ "$COMMIT_LIMIT" -gt 0 ]] && [[ "$COMMITTED_AS" -gt 0 ]]; then
        OVERCOMMIT_RATIO=$(awk "BEGIN {printf \"%.2f\", $COMMITTED_AS / $COMMIT_LIMIT}" 2>/dev/null)
        label "CommitLimit:"   "${COMMIT_LIMIT} MB (内核承诺的内存上限)"
        label "Committed_AS:"  "${COMMITTED_AS} MB (已承诺分配的内存)"
        label "承诺比率:"      "${OVERCOMMIT_RATIO}x"

        if (( $(echo "$COMMITTED_AS > $COMMIT_LIMIT" | bc -l 2>/dev/null) )); then
            bad "Committed_AS > CommitLimit！内存已超售，存在被 OOM Killer 的风险！"
            add_risk 8 "内存超售: Committed_AS(${COMMITTED_AS}MB) > CommitLimit(${COMMIT_LIMIT}MB)"
        elif (( $(echo "$OVERCOMMIT_RATIO > 0.8" | bc -l 2>/dev/null || echo 0) )); then
            warn "承诺比率较高 (${OVERCOMMIT_RATIO}x)，接近超售边界"
            if $BALLOON_ACTIVE; then
                bad "且 Balloon 驱动已加载，内存正处于超售状态！"
                add_risk 6 "承诺比率 ${OVERCOMMIT_RATIO}x + Balloon 活跃"
            else
                add_risk 3 "承诺比率 ${OVERCOMMIT_RATIO}x，接近超售边界"
            fi
        else
            good "承诺比率正常 (${OVERCOMMIT_RATIO}x)"
        fi
    else
        warn "无法读取 CommitLimit/Committed_AS"
        add_risk 3 "无法检测内存超售指标"
    fi

    # 5.2 SWAP 警示
    echo ""
    info "Swap 使用分析..."
    if [[ "$SWAP_TOTAL" -gt 0 ]]; then
        SWAP_RATIO=$(awk "BEGIN {printf \"%.2f\", $SWAP_TOTAL / $MEM_TOTAL}" 2>/dev/null)
        label "Swap/内存比:" "${SWAP_RATIO}"

        if (( $(echo "$SWAP_TOTAL > $MEM_TOTAL * 2" | bc -l 2>/dev/null || echo 0) )); then
            warn "Swap 量极大(是内存的 ${SWAP_RATIO}x)，可能是超售特征"
            add_risk 3 "Swap 远超内存，超售特征"
        fi

        if [[ "$SWAP_USED" -gt 100 ]] && [[ "$MEM_AVAIL" -gt 512 ]]; then
            warn "内存充裕但使用 Swap，可能是内存超售导致的强制换出"
            add_risk 3 "内存充裕但使用 Swap，可疑"
        fi
    fi

    # 5.3 overcommit_memory 参数
    echo ""
    info "检查内核内存超售策略..."
    if [[ -f /proc/sys/vm/overcommit_memory ]]; then
        OCM=$(cat /proc/sys/vm/overcommit_memory)
        case "$OCM" in
            0) label "overcommit_memory:" "0 (启发式 — 内核自行判断)";;
            1) label "overcommit_memory:" "1 (总是超售!)"
               warn "内核配置为总是超售内存!"
               add_risk 3 "overcommit_memory=1, 总是超售";;
            2) label "overcommit_memory:" "2 (严格不超售)"
               good "内核配置为不超售内存";;
        esac
    fi

    # 5.4 内存带宽简单测试 (检测内存争抢)
    echo ""
    info "内存带宽测试 (检测内存争抢)..."
    if [[ -d /dev/shm ]]; then
        # 写入测试
        if command -v dd &>/dev/null; then
            WB_MS=$( (dd if=/dev/zero of=/dev/shm/.mem_test bs=1M count=500 conv=fdatasync 2>&1 | grep -oP '[\d.]+(?= s)') || echo "")
            RR_MS=$( (dd if=/dev/shm/.mem_test of=/dev/null bs=1M count=500 2>&1 | grep -oP '[\d.]+(?= s)') || echo "")
            rm -f /dev/shm/.mem_test 2>/dev/null

            if [[ -n "$WB_MS" ]]; then
                WB_SPEED=$(awk "BEGIN {printf \"%.0f\", 500 / $WB_MS}")
                label "内存写入:" "${WB_SPEED} MB/s"

                # 如果已知 CPU 型号，可以估算预期内存带宽做对比
                if echo "$CPU_MODEL" | grep -qi "Xeon\|EPYC"; then
                    if [[ "$WB_SPEED" -lt 1000 ]]; then
                        warn "内存写入带宽偏低(${WB_SPEED} MB/s)，可能有内存争抢"
                        add_risk 2 "内存带宽 ${WB_SPEED} MB/s，偏低"
                    else
                        good "内存带宽正常"
                    fi
                fi
            fi

            if [[ -n "$RR_MS" ]]; then
                RR_SPEED=$(awk "BEGIN {printf \"%.0f\", 500 / $RR_MS}")
                label "内存读取:" "${RR_SPEED} MB/s"
            fi
        fi
    fi
    add_max 3
else
    warn "无法读取 /proc/meminfo"
    add_risk 8 "无法检测内存信息"
fi

# ============================================================
#  6. CPU 性能基准测试 (直接检测 CPU 分配性能)
# ============================================================
header "【第六步】CPU 性能基准测试"

add_max 5

if command -v sysbench &>/dev/null; then
    info "使用 sysbench 进行 CPU 基准测试 (素数计算)..."
    detail "测试单线程 CPU 性能..."

    P_OUTPUT=$(sysbench cpu --cpu-max-prime=20000 --threads=1 run 2>/dev/null || true)
    P_EVENTS=$(echo "$P_OUTPUT" | grep "total number of events" | grep -oP '[\d.]+' || echo "")
    P_TIME=$(echo "$P_OUTPUT" | grep "total time" | grep -oP '[\d.]+' | head -1 || echo "")
    P_EPS=$(echo "$P_OUTPUT" | grep "events per second" | grep -oP '[\d.]+' | head -1 || echo "")

    if [[ -n "$P_EPS" ]]; then
        label "单线程 EPS:" "${P_EPS} events/sec"
    fi

    # 再测多线程, 检测扩展效率
    echo ""
    info "测试多线程 CPU 性能 (${VCPU_COUNT} 线程)..."
    M_OUTPUT=$(sysbench cpu --cpu-max-prime=20000 --threads=$VCPU_COUNT run 2>/dev/null || true)
    M_EPS=$(echo "$M_OUTPUT" | grep "events per second" | grep -oP '[\d.]+' | head -1 || echo "")

    if [[ -n "$M_EPS" ]] && [[ -n "$P_EPS" ]] && [[ "$VCPU_COUNT" -gt 0 ]]; then
        label "多线程 EPS:"   "${M_EPS} events/sec"
        SCALING=$(awk "BEGIN {printf \"%.2f\", $M_EPS / ($P_EPS * $VCPU_COUNT)}" 2>/dev/null)
        label "扩展效率:"     "${SCALING} (1.0 = 完美线性)"

        if (( $(echo "$SCALING < 0.5" | bc -l 2>/dev/null || echo 0) )); then
            bad "多线程扩展效率极低(${SCALING})！vCPU 之间严重争抢物理核心"
            add_risk 5 "CPU扩展效率 ${SCALING}，vCPU 争抢严重"
        elif (( $(echo "$SCALING < 0.7" | bc -l 2>/dev/null || echo 0) )); then
            warn "多线程扩展效率偏低(${SCALING})，vCPU 争抢物理核心"
            add_risk 3 "CPU扩展效率 ${SCALING}，vCPU 有争抢"
        elif (( $(echo "$SCALING < 0.9" | bc -l 2>/dev/null || echo 0) )); then
            info "多线程扩展效率可接受(${SCALING})"
        else
            good "多线程扩展效率优秀(${SCALING})，接近线性扩展"
        fi

        # 使用扩展效率做超售判断
        if (( $(echo "$SCALING < 0.3" | bc -l 2>/dev/null || echo 0) )); then
            # 可能是 vCPU 远多于物理核心
            if [[ -n "$MAX_PHYSICAL_CORES" ]] && [[ "$MAX_PHYSICAL_CORES" -gt 0 ]]; then
                if [[ "$VCPU_COUNT" -gt "$MAX_PHYSICAL_CORES" ]]; then
                    bad "vCPU(${VCPU_COUNT}) > 物理核心(${MAX_PHYSICAL_CORES}) 且扩展效率极低(${SCALING})，CPU 严重超售!"
                    add_risk 5 "vCPU > 物理核心 + 扩展效率极低"
                fi
            fi
        fi
    fi

elif command -v openssl &>/dev/null; then
    info "使用 openssl speed 进行 CPU 性能测试..."
    OSSL_OUTPUT=$(openssl speed -evp aes-256-cbc -bytes 65536 -seconds 2 2>/dev/null || true)
    OSSL_SPEED=$(echo "$OSSL_OUTPUT" | grep -oP '\d+[\d.]*(?=k)' | head -1 || echo "")

    if [[ -n "$OSSL_SPEED" ]]; then
        label "AES-256-CBC:" "${OSSL_SPEED} kB/s"
        # 单线程下, AES-256-CBC 在现代 CPU 上通常 > 500 MB/s
        if (( $(echo "$OSSL_SPEED < 100000" | bc -l 2>/dev/null || echo 0) )); then
            warn "AES 加密性能偏低(${OSSL_SPEED} kB/s)，CPU 分配可能不足"
            add_risk 2 "AES 性能偏低"
        else
            good "AES 加密性能正常"
        fi
    fi
fi

# ============================================================
#  7. 磁盘 IO 超售检测
# ============================================================
header "【第七步】磁盘 IO 超售检测"

add_max 5

# 7.1 连续写入
echo ""
info "连续写入测试 (256MB 顺序写入)..."
if [[ -w /tmp ]]; then
    DD_OUT=$(dd if=/dev/zero of=/tmp/.io_test bs=1M count=256 conv=fdatasync 2>&1)
    DD_TIME=$(echo "$DD_OUT" | grep -oP '[\d.]+(?= s)' | head -1)
    DD_SPEED=$(echo "$DD_OUT" | grep -oP '[\d.]+(?= MB/s)' | head -1)

    if [[ -n "$DD_TIME" ]]; then
        label "写入耗时:" "${DD_TIME}s"
        label "写入速度:" "${DD_SPEED:-未知} MB/s"

        if (( $(echo "$DD_TIME > 8.0" | bc -l 2>/dev/null || echo 0) )); then
            bad "磁盘连续写入极慢(${DD_TIME}s)，IO 严重超售"
            add_risk 5 "磁盘写入 ${DD_TIME}s，IO 严重超售"
        elif (( $(echo "$DD_TIME > 3.0" | bc -l 2>/dev/null || echo 0) )); then
            warn "磁盘写入较慢(${DD_TIME}s)，IO 可能有争抢"
            add_risk 3 "磁盘写入 ${DD_TIME}s，IO 争抢"
        elif (( $(echo "$DD_TIME > 1.0" | bc -l 2>/dev/null || echo 0) )); then
            info "磁盘写入速度一般(${DD_TIME}s)"
        else
            good "磁盘写入速度正常(${DD_TIME}s)"
        fi
    fi

    # 7.2 4K 随机写入 (IOPS 测试)
    echo ""
    info "4K 随机写入测试 (IOPS — 对超售最敏感的磁盘指标)..."
    DD_RAND=$(dd if=/dev/zero of=/tmp/.io_rand_test bs=4k count=25000 conv=fdatasync 2>&1)
    RAND_TIME=$(echo "$DD_RAND" | grep -oP '[\d.]+(?= s)' | head -1)
    RAND_SPEED=$(echo "$DD_RAND" | grep -oP '[\d.]+(?= MB/s)' | head -1)

    if [[ -n "$RAND_TIME" ]]; then
        if (( $(echo "$RAND_TIME > 0" | bc -l 2>/dev/null) )); then
            IOPS=$(awk "BEGIN {printf \"%.0f\", 25000 / $RAND_TIME}" 2>/dev/null)
        else
            IOPS=0
        fi
        label "4K 随机耗时:"   "${RAND_TIME}s"
        label "估算 IOPS:"    "${IOPS:-0}"

        if [[ -n "$IOPS" ]] && [[ "$IOPS" -gt 0 ]]; then
            if [[ "$IOPS" -lt 100 ]]; then
                bad "IOPS 极低(${IOPS})，磁盘严重超售或使用了机械盘做虚拟化存储"
                add_risk 5 "IOPS=${IOPS}，磁盘严重超售"
            elif [[ "$IOPS" -lt 500 ]]; then
                warn "IOPS 偏低(${IOPS})，磁盘 IO 存在明显争抢"
                add_risk 3 "IOPS=${IOPS}，IO 争抢"
            elif [[ "$IOPS" -lt 2000 ]]; then
                info "IOPS 尚可(${IOPS})"
            else
                good "IOPS 良好(${IOPS})，磁盘性能不错"
            fi
        fi
    fi

    # 清理
    rm -f /tmp/.io_test /tmp/.io_rand_test 2>/dev/null
fi

# 检查磁盘类型
echo ""
info "检测磁盘物理类型..."
if lsblk -d -o NAME,ROTA 2>/dev/null | grep -v "^NAME" | grep -q "0"; then
    good "检测到 SSD/NVMe (非机械盘)"
else
    # 通过 sysfs
    SSD_FOUND=false
    for rfile in /sys/block/*/queue/rotational; do
        if [[ -f "$rfile" ]] && [[ "$(cat "$rfile")" == "0" ]]; then
            SSD_FOUND=true; break
        fi
    done
    if $SSD_FOUND; then
        good "检测到 SSD/NVMe"
    else
        warn "可能使用机械盘 (HDD)，虚拟化存储性能受限"
        add_risk 2 "可能使用 HDD"
    fi
fi

# ============================================================
#  8. NUMA 拓扑与中断分析
# ============================================================
header "【第八步】NUMA 拓扑与中断分布分析"

add_max 3

# 8.1 NUMA 拓扑
echo ""
info "NUMA 拓扑分析..."
if [[ "$NUMA_NODES" -gt 1 ]]; then
    info "检测到 ${NUMA_NODES} 个 NUMA 节点"
    if [[ "$VCPU_COUNT" -gt 0 ]] && [[ "$NUMA_NODES" -gt 0 ]]; then
        VCPU_PER_NUMA=$((VCPU_COUNT / NUMA_NODES))
        label "每 NUMA 节点 vCPU:" "${VCPU_PER_NUMA}"

        # 如果单 NUMA 节点 vCPU 很少但 NUMA 节点多，说明宿主有多个物理 CPU
        if [[ "$NUMA_NODES" -ge 2 ]] && [[ "$VCPU_PER_NUMA" -le 2 ]]; then
            warn "vCPU 分散在 ${NUMA_NODES} 个 NUMA 节点上"
            warn "vCPU 跨 NUMA 节点会导致内存访问延迟增加"
            add_risk 2 "vCPU 跨 ${NUMA_NODES} 个 NUMA 节点"

            # 可能是宿主有多个物理 CPU socket 但只分了少量 vCPU
            if [[ "$NUMA_NODES" -ge 2 ]] && [[ "$VCPU_PER_NUMA" -le 1 ]]; then
                warn "每个 NUMA 节点仅 1 个 vCPU，隔离性差但无超售特征（也可能是宿主大机器）"
                # 不一定是超售
            fi
        fi
    fi
else
    info "单 NUMA 节点配置"
fi

# 8.2 中断分布
echo ""
info "中断分布分析..."
if [[ -f /proc/interrupts ]]; then
    INT_COUNT=$(head -1 /proc/interrupts 2>/dev/null | wc -w)
    label "CPU 数量:"    "${VCPU_COUNT}"
    label "中断列数:"    "$((INT_COUNT - 1))"

    # 检查中断是否均衡分布在所有 vCPU 上
    IMBALANCE=false
    TOTAL_INT=0
    declare -a CPU_INTS
    for ((i=0; i<VCPU_COUNT; i++)); do
        CI=0
        while IFS= read -r line; do
            VAL=$(echo "$line" | awk "{print \$$((i+2))}" 2>/dev/null | grep -oP '\d+' || echo 0)
            CI=$((CI + VAL))
        done < <(grep -v "CPU\|NMI\|LOC\|TLB\|TRM\|THR\|SPU\|RES\|CAL\|TAS\|ERR\|MIS" /proc/interrupts 2>/dev/null)
        CPU_INTS[$i]=$CI
        TOTAL_INT=$((TOTAL_INT + CI))
    done

    if [[ "$TOTAL_INT" -gt 0 ]] && [[ "$VCPU_COUNT" -gt 0 ]]; then
        AVG_INT=$((TOTAL_INT / VCPU_COUNT))
        for ((i=0; i<VCPU_COUNT; i++)); do
            if [[ "$AVG_INT" -gt 0 ]]; then
                DEV=$(( ${CPU_INTS[$i]} * 100 / AVG_INT ))
                if [[ "$DEV" -lt 50 ]] || [[ "$DEV" -gt 150 ]]; then
                    IMBALANCE=true
                fi
            fi
        done

        if $IMBALANCE; then
            warn "终端分布不均衡，部分 vCPU 可能未 pinning 或中断亲和性未优化"
        else
            info "终端分布相对均衡"
        fi
    fi
fi

# ============================================================
#  9. 综合评分与结论
# ============================================================
header "【综合评分】超售检测结论"

# 确保 MAX_SCORE 不为 0
[[ "$MAX_SCORE" -eq 0 ]] && MAX_SCORE=100

SCORE_PCT=$(awk "BEGIN {printf \"%d\", ($RISK_SCORE * 100) / $MAX_SCORE}" 2>/dev/null)
[[ -z "$SCORE_PCT" ]] && SCORE_PCT=0

echo -e ""
echo -e "  ${BOLD}宿主机超售风险评估${NC}"
echo -e "  ─────────────────────────────"
label "虚拟化类型:"     "KVM"
label "风险总分:"       "${RISK_SCORE} / ${MAX_SCORE}"
label "超售风险指数:"   "${SCORE_PCT}%"

# 超售指数归一化为 0-100 时，做分级
# 但 SCORE_PCT 已经是百分比了
if [[ "$SCORE_PCT" -le 10 ]] && [[ "$RISK_SCORE" -le 3 ]]; then
    GRADE="${GREEN}A${NC}"
    DESC="几乎无超售迹象，宿主机资源配置良好"
elif [[ "$SCORE_PCT" -le 20 ]]; then
    GRADE="${GREEN}A${NC}"
    DESC="几乎无超售迹象，宿主机资源配置良好"
elif [[ "$SCORE_PCT" -le 35 ]]; then
    GRADE="${GREEN}B${NC}"
    DESC="轻度超售，日常使用影响不大，高峰期可能有轻微波动"
elif [[ "$SCORE_PCT" -le 50 ]]; then
    GRADE="${YELLOW}C${NC}"
    DESC="中度超售，高峰期能明显感受到性能下降"
elif [[ "$SCORE_PCT" -le 70 ]]; then
    GRADE="${RED}D${NC}"
    DESC="严重超售，性能不稳定，建议联系服务商或考虑迁移"
else
    GRADE="${RED}F${NC}"
    DESC="极度超售！宿主机资源严重不足，强烈建议立即更换服务商"
fi

echo -e "  ${BOLD}超售等级:${NC}  ${GRADE}"
echo -e "  ${BOLD}评估意见:${NC}  ${DESC}"
echo ""

# 打印关键风险项
echo -e "${BOLD}关键风险项明细:${NC}"
if [[ ${#REPORT_LINES[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}未检测到明显超售迹象${NC}"
else
    # 按权重排序
    IFS=$'\n'
    SORTED_LINES=($(sort -t'+' -k2 -rn <<< "${REPORT_LINES[*]}"))
    unset IFS

    for line in "${SORTED_LINES[@]}"; do
        WEIGHT=$(echo "$line" | grep -oP '(?<=\+)\d+' | head -1)
        DESC=$(echo "$line" | sed 's/^+[0-9]*://')
        if [[ "$WEIGHT" -ge 6 ]]; then
            echo -e "  ${RED}[严重]${NC} ${DESC} (权重: +${WEIGHT})"
        elif [[ "$WEIGHT" -ge 3 ]]; then
            echo -e "  ${YELLOW}[中等]${NC} ${DESC} (权重: +${WEIGHT})"
        else
            echo -e "  ${NC}[轻微]${NC} ${DESC} (权重: +${WEIGHT})"
        fi
    done
fi

echo ""
echo -e "${MAGENTA}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║  检测完毕                                    ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "检测说明:"
echo -e "  1. CPU Steal Time 是判断 CPU 超售的最核心指标 (>10% 即为超售)"
echo -e "  2. L3 Cache 分析可估算宿主机物理核心数，对比 vCPU 发现超售"
echo -e "  3. virtio_balloon 驱动加载 = 内存正在被超售"
echo -e "  4. CPU 扩展效率 < 0.5 说明 vCPU 争抢物理核心严重"
echo -e "  5. IOPS < 500 通常说明存储层超售严重"
echo -e "  6. 建议在业务高峰期再次运行以获得更准确的结果"
echo -e ""
echo -e "  ${YELLOW}注意: 单次检测有一定局限性，建议结合多次检测结果综合判断${NC}"
echo ""
