#!/bin/bash
# ============================================================
#  KVM 宿主机超售 & 邻居 VM 探测脚本 v3.0
#  从虚拟机内部:
#    1. 检测 KVM 宿主机是否超售
#    2. 探测同宿主机的其他 KVM 虚拟机
#    3. 收集宿主机暴露的硬件信息
# ============================================================
#  技术原理:
#    - KVM CPUID leaves (0x40000000+) 暴露宿主机内核版本等信息
#    - SMBIOS/DMI 暴露硬件信息
#    - 虚拟网络 (virbr0 NAT) 上可能发现其他 VM
#    - Steal Time 波动模式分析推断邻居活动
#    - L3 Cache 对比分析推算物理核心数
#    - virtio_balloon 活动记录判断内存超售
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
DIM='\033[2m'
NC='\033[0m'

# ---------- 全局变量 ----------
RISK_SCORE=0
MAX_SCORE=0
REPORT_LINES=()
VIRT_TYPE="unknown"
IS_KVM=false

# 邻居 VM 探测
NEIGHBOR_FOUND=false
NEIGHBOR_COUNT=0
NEIGHBOR_LIST=""

# CPU 相关
VCPU_COUNT=0
CPU_MODEL=""
CPU_SOCKETS=0
CPU_CORES_PER_SOCKET=0
CPU_THREADS_PER_CORE=0
L3_CACHE_SIZE=""

# ---------- 辅助函数 ----------
info()    { echo -e "${CYAN}[信息]${NC} $1"; }
good()    { echo -e "${GREEN}[通过]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
bad()     { echo -e "${RED}[异常]${NC} $1"; }
header()  { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }
label()   { printf "  %-30s %s\n" "$1" "$2"; }
sub()     { echo -e "  ${DIM}$1${NC}"; }

add_risk() { local w=$1 d=$2; RISK_SCORE=$((RISK_SCORE + w)); REPORT_LINES+=("+${w}:${d}"); }
add_max()  { MAX_SCORE=$((MAX_SCORE + $1)); }

# 用颜色标记值
color_val() {
    local val=$1
    local warn_thresh=$2
    local bad_thresh=$3
    if (( $(echo "$val >= $bad_thresh" | bc -l 2>/dev/null || echo 0) )); then
        echo -e "${RED}${val}${NC}"
    elif (( $(echo "$val >= $warn_thresh" | bc -l 2>/dev/null || echo 0) )); then
        echo -e "${YELLOW}${val}${NC}"
    else
        echo -e "${GREEN}${val}${NC}"
    fi
}

check_cmd() { command -v "$1" &>/dev/null; }

# ---------- 检查 root ----------
if [[ $EUID -ne 0 ]]; then
    warn "部分检测需要 root 权限，建议以 root 运行以获得完整结果"
fi

# ============================================================
echo -e ""
echo -e "${MAGENTA}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║    KVM 宿主机超售 & 邻居 VM 探测 v3.0              ║${NC}"
echo -e "${MAGENTA}║    从虚拟机内部穿透检测宿主机                      ║${NC}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "  ${DIM}技术说明: KVM 隔离设计阻止 VM 直接看到其他 VM，${NC}"
echo -e "  ${DIM}本脚本通过旁路信息（网络、时序、缓存、内核参数等）推断宿主机状态。${NC}"
echo -e "  ${DIM}结果仅供参考，不保证 100% 准确。${NC}"
echo -e ""

# ============================================================
#  1. 验证虚拟化环境
# ============================================================
header "【第一步】验证虚拟化环境"

if command -v systemd-detect-virt &>/dev/null; then
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    if [[ "$VIRT_TYPE" == "kvm" || "$VIRT_TYPE" == "qemu" ]]; then
        IS_KVM=true
    fi
fi

# CPU 特征检测（补充: /proc/cpuinfo 中的 KVM 标志）
if grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null; then
    if grep -qi "KVM\|QEMU" /proc/cpuinfo 2>/dev/null; then
        IS_KVM=true
    fi
fi

# 补充: 通过 hypervisor 类型检测
if [[ -d /sys/hypervisor ]] && [[ -f /sys/hypervisor/type ]]; then
    HVTYPE=$(cat /sys/hypervisor/type 2>/dev/null)
    [[ "$HVTYPE" == "kvm" ]] && IS_KVM=true
fi

if ! $IS_KVM; then
    warn "未检测到 KVM 虚拟化！当前: ${VIRT_TYPE}"
    warn "非 KVM 环境，部分检测项不可用，但会尽量执行"
else
    good "确认 KVM 虚拟化环境 (${VIRT_TYPE})"
fi
add_max 5

# ============================================================
#  2. 宿主机 KVM 内核信息 (CPUID 深度探测)
# ============================================================
header "【第二步】宿主机 KVM 内核与 CPU 信息探测（穿透检测）"

# 2.1 CPUID KVM 叶子信息
info "检测 KVM CPUID leaves（直接向宿主机 KVM 模块查询）..."
if command -v cpuid &>/dev/null; then
    for leaf in 0x40000000 0x40000001 0x40000002 0x40000003 0x40000004 0x40000010; do
        CPUID_OUT=$(cpuid -1 -l $leaf 2>/dev/null || true)
        if [[ -n "$CPUID_OUT" ]]; then
            # KVM 签名
            if echo "$CPUID_OUT" | grep -qi "KVMKVMKVM\|Linux\|KVM"; then
                EAX=$(echo "$CPUID_OUT" | grep -i "eax" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "")
                EBX=$(echo "$CPUID_OUT" | grep -i "ebx" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "")
                ECX=$(echo "$CPUID_OUT" | grep -i "ecx" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "")
                EDX=$(echo "$CPUID_OUT" | grep -i "edx" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "")

                case $leaf in
                    0x40000000)
                        # KVM 签名和最大叶子
                        if [[ -n "$EBX" && -n "$ECX" && -n "$EDX" ]]; then
                            # 从 CPUID 寄存器解码 KVM 签名 (KVMKVMKVM)
                            KVM_SIG_RAW=$(printf "0x%08x%08x%08x" "$EAX" "$EBX" "$ECX" 2>/dev/null || echo "raw")
                            label "KVM 签名(EAX,EBX,ECX):" "${KVM_SIG_RAW}"
                        fi
                        label "最大 CPUID 叶子:" "$(echo "$CPUID_OUT" | grep "eax" | head -1 | grep -oP '0x[0-9a-fA-F]+')"
                        ;;
                    0x40000001)
                        # KVM 版本: eax = 版本号
                        if [[ -n "$EAX" ]]; then
                            KVM_VERSION_DEC=$((EAX))
                            KVM_MAJOR=$(( (KVM_VERSION_DEC >> 16) & 0xFF ))
                            KVM_MINOR=$(( (KVM_VERSION_DEC >> 8) & 0xFF ))
                            KVM_PATCH=$(( KVM_VERSION_DEC & 0xFF ))
                            label "KVM 版本:" "${KVM_MAJOR}.${KVM_MINOR}.${KVM_PATCH}"

                            # 从 KVM 版本可推断宿主机内核版本
                            if [[ "$KVM_MAJOR" -ge 5 ]]; then
                                good "KVM 版本较新 (${KVM_MAJOR}.${KVM_MINOR})，宿主机内核较新"
                            elif [[ "$KVM_MAJOR" -lt 4 ]]; then
                                warn "KVM 版本较旧 (${KVM_MAJOR}.${KVM_MINOR})，宿主机内核较老，可能缺乏优化"
                                add_risk 1 "KVM 版本 ${KVM_MAJOR}.${KVM_MINOR} 较旧"
                            fi

                            # KVM 特性标志在 ebx
                            if [[ -n "$EBX" ]]; then
                                FEAT_DEC=$((EBX))
                                label "KVM 特性标志:" "0x$(printf '%x' $FEAT_DEC)"

                                # 检查特定特性位 (bit 0 = KVM_FEATURE_CLOCKSOURCE)
                                if (( FEAT_DEC & 1 )); then
                                    sub "支持 KVM_CLOCKSOURCE (PV 时钟)"
                                fi
                                if (( FEAT_DEC & 2 )); then
                                    sub "支持 KVM_CLOCKSOURCE2 (PV 时钟 v2)"
                                fi
                            fi
                        fi
                        ;;
                    0x40000002)
                        # KVM PV 特性
                        if [[ -n "$EAX" ]]; then
                            PV_FEAT=$((EAX))
                            label "PV 特性 EAX:" "0x$(printf '%x' $PV_FEAT)"
                            if (( PV_FEAT & (1<<0) )); then
                                sub "支持 PV EOI (加速中断处理)"
                            fi
                        fi
                        ;;
                    0x40000010)
                        # KVM PV clock info
                        label "KVM PV Clock leaf:" "${EAX:-未知}"
                        ;;
                esac
            fi
        fi
    done

    # 尝试读取 0x40000100 (Hyper-V enlightenments)
    HV_CPUID=$(cpuid -1 -l 0x40000100 2>/dev/null || true)
    if [[ -n "$HV_CPUID" ]] && echo "$HV_CPUID" | grep -qi "eax"; then
        # 检查 Hyper-V 兼容性
        sub "存在 Hyper-V enlightenment CPUID 叶子"
    fi
else
    info "未安装 cpuid 工具，可以通过以下命令安装:"
    info "  apt install cpuid   (Debian/Ubuntu)"
    info "  yum install cpuid   (CentOS/RHEL)"
    info "  (不安装也能检测，但信息会更少)"
fi
add_max 3

# 2.2 DMI 信息探测
echo ""
info "从 DMI/SMBIOS 读取宿主机暴露的硬件信息..."
if [[ -d /sys/class/dmi/id ]]; then
    for dmi_entry in product_name product_version sys_vendor bios_vendor bios_version board_name board_vendor; do
        if [[ -f "/sys/class/dmi/id/$dmi_entry" ]]; then
            VAL=$(cat "/sys/class/dmi/id/$dmi_entry" 2>/dev/null || true)
            [[ -n "$VAL" ]] && label "DMI ${dmi_entry}:" "$VAL"
        fi
    done
else
    warn "无法读取 DMI 信息（无 /sys/class/dmi/id）"
fi
add_max 2

# 2.3 宿主机内核版本推断
echo ""
info "通过 KVM 时钟源推断宿主机信息..."
if [[ -f /sys/devices/system/clocksource/clocksource0/current_clocksource ]]; then
    CLK_SRC=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null)
    label "当前时钟源:" "${CLK_SRC}"
    if [[ "$CLK_SRC" == "kvm-clock" ]]; then
        good "使用 KVM PV 时钟，时间性能良好"
    fi
fi

# 检查有没有 kvm 内核模块信息暴露
if [[ -d /sys/module/kvm ]] || [[ -d /sys/module/kvm_intel ]] || [[ -d /sys/module/kvm_amd ]]; then
    # 注意: 这是 guest 内的 kvm 模块，不是 host 的
    label "KVM 模块:" "$(ls /sys/module/ 2>/dev/null | grep kvm | tr '\n' ' ')"
fi

# 检查 kvm 参数
for param in /sys/module/kvm/parameters/*; do
    if [[ -f "$param" ]]; then
        pname=$(basename "$param")
        pval=$(cat "$param" 2>/dev/null)
        [[ -n "$pval" ]] && label "KVM 参数 ${pname}:" "${pval}"
    fi
done 2>/dev/null || true

# ============================================================
#  3. CPU 超售深度检测
# ============================================================
header "【第三步】CPU 超售深度检测"

# CPU 基本信息
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | sed 's/.*:\s*//')
VCPU_COUNT=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
THREADS_PER_CORE=$(lscpu 2>/dev/null | grep "Thread(s) per core" | awk '{print $NF}')
CORES_PER_SOCKET=$(lscpu 2>/dev/null | grep "Core(s) per socket" | awk '{print $NF}')
SOCKETS=$(lscpu 2>/dev/null | grep "Socket(s)" | awk '{print $NF}')
NUMA_NODES=$(lscpu 2>/dev/null | grep "NUMA node(s)" | awk '{print $NF}')

[[ -z "$THREADS_PER_CORE" ]] && THREADS_PER_CORE=1
[[ -z "$CORES_PER_SOCKET" ]] && CORES_PER_SOCKET=$VCPU_COUNT
[[ -z "$SOCKETS" ]] && SOCKETS=1
[[ -z "$NUMA_NODES" ]] && NUMA_NODES=1

label "CPU 型号:"         "${CPU_MODEL:-未知}"
label "vCPU 总数:"        "${VCPU_COUNT}"
label "每 Socket 核心:"   "${CORES_PER_SOCKET}"
label "每核心线程:"       "${THREADS_PER_CORE}"
label "Socket 数:"        "${SOCKETS}"
label "NUMA 节点:"        "${NUMA_NODES}"

# 3.1 CPU 透传模式检测
echo ""
info "CPU 透传模式检测..."
if echo "$CPU_MODEL" | grep -qi "QEMU Virtual\|Common KVM"; then
    warn "CPU 为 QEMU 通用模拟模式（非透传），宿主机隐藏了真实 CPU 型号"
    warn "这是 VPS 服务商常见做法，但不影响超售检测（仍可通过其他方式分析）"
    add_risk 1 "CPU 非透传模式"
else
    good "CPU 为透传/半透传模式，可看到真实型号"
fi

# 3.2 L3 Cache 推算物理核心数 (核心穿透技术)
echo ""
info "L3 Cache 推算宿主机物理核心数..."
L3_CACHE_FOUND=false
for cache_idx in /sys/devices/system/cpu/cpu0/cache/index*/; do
    if [[ -f "${cache_idx}type" ]]; then
        CTYPE=$(cat "${cache_idx}type" 2>/dev/null)
        if [[ "$CTYPE" == "Unified" ]]; then
            L3_CACHE_SIZE=$(cat "${cache_idx}size" 2>/dev/null)
            L3_CACHE_FOUND=true
            break
        fi
    fi
done

if ! $L3_CACHE_FOUND; then
    L3_CACHE_SIZE=$(lscpu 2>/dev/null | grep "L3" | awk '{print $NF}' | sed 's/[A-Z]//g' || echo "")
fi

# Intel L3 数据库: [L3大小MB]=物理核心数:架构代际
declare -A INTEL_L3_MAP
INTEL_L3_MAP["60"]="56:4th Gen Xeon (Sapphire Rapids - 56核)"
INTEL_L3_MAP["57"]="56:4th Gen Xeon"
INTEL_L3_MAP["105"]="56:4th Gen Xeon (Sapphire Rapids - 56核)"
INTEL_L3_MAP["45"]="36:3rd Gen Xeon (Ice Lake - 36核)"
INTEL_L3_MAP["42"]="28:3rd Gen Xeon (Ice Lake - 28核)"
INTEL_L3_MAP["30"]="24:3rd Gen Xeon (Ice Lake - 24核)"
INTEL_L3_MAP["38.5"]="28:2nd Gen Xeon (Cascade Lake - 28核)"
INTEL_L3_MAP["33"]="24:2nd Gen Xeon (24核)"
INTEL_L3_MAP["27.5"]="20:2nd Gen Xeon (20核)"
INTEL_L3_MAP["24.75"]="18:2nd Gen Xeon (18核)"
INTEL_L3_MAP["22"]="16:2nd Gen Xeon (16核)"
INTEL_L3_MAP["16.5"]="12:2nd Gen Xeon (12核)"
INTEL_L3_MAP["11"]="8:2nd Gen Xeon (8核)"
INTEL_L3_MAP["36"]="24:Raptor Lake (24核/32线程)"
INTEL_L3_MAP["30"]="16:Alder Lake (16核/24线程)"
INTEL_L3_MAP["25"]="12:i7-12700 (12核)"
INTEL_L3_MAP["18"]="10:i5-12600 (10核)"
INTEL_L3_MAP["20"]="8:i7-10700 (8核)"
INTEL_L3_MAP["16"]="8:第8-10代酷睿/E-系列"
INTEL_L3_MAP["12"]="6:第8-10代酷睿i5"
INTEL_L3_MAP["8"]="4:第8-10代酷睿i3"
INTEL_L3_MAP["9"]="6:低功耗/移动端"
INTEL_L3_MAP["6"]="4:低功耗/移动端"
INTEL_L3_MAP["3"]="2:低功耗/移动端"

# AMD EPYC L3 数据库: [每CCD L3]=8核心 (EPYC 架构)
# Genoa 每 CCD 32MB, Milan 每 CCD 32MB, Rome 每 CCD 32MB
# Naples 每 CCD 8MB

if [[ -n "$L3_CACHE_SIZE" ]]; then
    L3_NUM=$(echo "$L3_CACHE_SIZE" | grep -oP '[\d.]+' | head -1)
    label "L3 Cache 大小:" "${L3_NUM} MB"

    # 根据 CPU 厂商选择不同推算方法
    if echo "${CPU_MODEL}" | grep -qi "Intel"; then
        info "Intel 架构 → 通过 L3 大小推算物理核心数"
        PHYSICAL_CORES_EST=0
        for l3size in "${!INTEL_L3_MAP[@]}"; do
            if (( $(echo "$L3_NUM >= $l3size * 0.95 && $L3_NUM <= $l3size * 1.05" | bc -l 2>/dev/null) )); then
                IFS=':' read -r cores desc <<< "${INTEL_L3_MAP[$l3size]}"
                PHYSICAL_CORES_EST=$cores
                label "匹配物理 CPU:" "${desc}"
                break
            fi
        done

        if [[ "$PHYSICAL_CORES_EST" -eq 0 ]]; then
            # 用通用公式: Intel Xeon L3 ≈ 1.375MB/核
            PHYSICAL_CORES_EST=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 1.375}" 2>/dev/null)
            label "估算物理核心(通用):" "${PHYSICAL_CORES_EST} 核 (1.375MB L3/核)"
        fi

    elif echo "${CPU_MODEL}" | grep -qi "AMD\|Hygon"; then
        info "AMD/EPYC 架构 → 通过 L3 大小推算 CCD 数量"
        # AMD EPYC: 每 CCD = 8 核, 共享 L3
        # Genoa/Milan/Rome: 每 CCD 32MB L3
        # Naples: 每 CCD 8MB L3

        if (( $(echo "$L3_NUM >= 128" | bc -l 2>/dev/null) )); then
            # 大 L3 → EPYC 三代/四代
            CCD_COUNT=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 32}" 2>/dev/null)
            PHYSICAL_CORES_EST=$((CCD_COUNT * 8))
            label "估算 CCD 数:" "${CCD_COUNT} (每 CCD 32MB L3)"
            label "估算物理核心:" "${PHYSICAL_CORES_EST} 核 (8核/CCD)"
        elif (( $(echo "$L3_NUM >= 64" | bc -l 2>/dev/null) )); then
            CCD_COUNT=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 32}" 2>/dev/null)
            PHYSICAL_CORES_EST=$((CCD_COUNT * 8))
            label "估算 CCD 数:" "${CCD_COUNT}"
            label "估算物理核心:" "${PHYSICAL_CORES_EST} 核 (可能混搭)"
        else
            # Naples 或消费级
            CCD_COUNT=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 8}" 2>/dev/null)
            PHYSICAL_CORES_EST=$((CCD_COUNT * 8))
            label "估算物理核心(AMD):" "${PHYSICAL_CORES_EST} 核 (8MB L3/CCD)"
        fi
    else
        # 未知架构，用保守估算
        info "未知 CPU 架构，使用保守 L3 估算"
        PHYSICAL_CORES_EST=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 1.5}" 2>/dev/null)
        [[ "$PHYSICAL_CORES_EST" -lt 2 ]] && PHYSICAL_CORES_EST=2
        label "估算物理核心:" "${PHYSICAL_CORES_EST} 核 (通用估算)"
    fi

    add_max 8

    # 对比 vCPU 数量和估算物理核心数
    if [[ "$PHYSICAL_CORES_EST" -gt 0 ]] && [[ "$VCPU_COUNT" -gt 0 ]]; then
        echo ""
        info "vCPU vs 物理核心对比分析..."

        # 考虑超线程: 物理核心数*(超线程因子)
        MAX_PHYSICAL_WITH_HT=$((PHYSICAL_CORES_EST * 2))
        VCPU_RATIO_BASE=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / $PHYSICAL_CORES_EST}" 2>/dev/null)
        VCPU_RATIO_HT=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / $MAX_PHYSICAL_WITH_HT}" 2>/dev/null)

        label "vCPU/物理核心比:" "${VCPU_RATIO_BASE}x"
        label "vCPU/物理线程比:" "${VCPU_RATIO_HT}x"

        if (( $(echo "$VCPU_RATIO_BASE > 4.0" | bc -l 2>/dev/null || echo 0) )); then
            bad "vCPU 是物理核心 ${VCPU_RATIO_BASE}倍！严重超售！"
            bad "物理核心(${PHYSICAL_CORES_EST}) 被分配了 ${VCPU_COUNT} 个 vCPU"
            add_risk 10 "vCPU/核心=${VCPU_RATIO_BASE}x，严重超售"
        elif (( $(echo "$VCPU_RATIO_BASE > 2.0" | bc -l 2>/dev/null || echo 0) )); then
            bad "vCPU 是物理核心 ${VCPU_RATIO_BASE}倍！明显超售（超线程上限为 2x）"
            add_risk 7 "vCPU/核心=${VCPU_RATIO_BASE}x，明显超售"
        elif (( $(echo "$VCPU_RATIO_BASE > 1.0" | bc -l 2>/dev/null || echo 0) )); then
            warn "vCPU 超过物理核心数 (${VCPU_RATIO_BASE}x)，存在超售"
            add_risk 4 "vCPU/核心=${VCPU_RATIO_BASE}x，存在超售"
        else
            if (( $(echo "$VCPU_RATIO_HT <= 1.0" | bc -l 2>/dev/null || echo 0) )); then
                good "vCPU 数在物理线程数范围内，配置合理"
            else
                info "vCPU 数略超过物理线程数，轻度超售范围内"
                add_risk 2 "vCPU/线程=${VCPU_RATIO_HT}x"
            fi
        fi
    fi
else
    warn "无法读取 L3 Cache 大小"
    add_risk 3 "无法通过 L3 Cache 推算物理核心"
fi
add_max 3

# ============================================================
#  4. CPU Steal Time + 邻居活动检测
# ============================================================
header "【第四步】CPU Steal Time + 邻居 VM 活动检测"

STEAL_AVAILABLE=false
if [[ -f /proc/stat ]]; then
    COLUMNS=$(awk '/^cpu / {print NF-1}' /proc/stat 2>/dev/null)
    [[ "$COLUMNS" -ge 8 ]] && STEAL_AVAILABLE=true
fi

if $STEAL_AVAILABLE; then
    info "Steal Time 深度采样（检测 CPU 争抢及邻居 VM 活动模式）..."
    add_max 15

    # 定义采样函数
    steal_sample() {
        local duration=$1
        local background_load=$2
        local S1 T1 S2 T2
        local pid=""

        if [[ -n "$background_load" ]]; then
            eval "$background_load" &
            pid=$!
            sleep 1
        fi

        read S1 T1 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)
        sleep "$duration"
        read S2 T2 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)

        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true

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

    # 4.1 空闲态 Steal
    info "测试 1/5: 空闲状态 Steal Time (3 次采样取平均)..."
    TOTAL=0; VALID=0
    for i in 1 2 3; do
        R=$(steal_sample 2 "" "")
        if [[ "$R" != "-1" ]]; then
            TOTAL=$(awk "BEGIN {printf \"%.2f\", $TOTAL + $R}")
            VALID=$((VALID + 1))
        fi
        sleep 0.5
    done
    [[ "$VALID" -gt 0 ]] && AVG_IDLE=$(awk "BEGIN {printf \"%.2f\", $TOTAL / $VALID}") || AVG_IDLE=0
    label "空闲 Steal:" "$(color_val $AVG_IDLE 3 10)%"

    # 4.2 单线程负载 Steal
    info "测试 2/5: 单线程负载 Steal..."
    R_LOAD=$(steal_sample 3 "sha256sum /dev/zero >/dev/null 2>&1 & sleep 2; kill \$! 2>/dev/null" "")
    [[ "$R_LOAD" == "-1" ]] && R_LOAD=0
    label "单线程 Steal:" "$(color_val $R_LOAD 5 15)%"

    # 4.3 全核满载 Steal
    info "测试 3/5: 全 vCPU 满载 Steal..."
    PIDS=""
    for ((i=0; i<VCPU_COUNT; i++)); do
        sha256sum /dev/zero >/dev/null 2>&1 &
        PIDS="$PIDS $!"
    done
    sleep 1
    R_FULL=$(steal_sample 4 "" "")
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done 2>/dev/null
    [[ -z "$R_FULL" || "$R_FULL" == "-1" ]] && R_FULL=0
    label "满载 Steal:" "$(color_val $R_FULL 10 25)%"

    # 4.4 Steal 波动检测 + 邻居活动模式
    info "测试 4/5: Steal 时序波动分析（检测邻居 VM 活动模式）..."
    echo ""
    sub "  快速采样 8 次 (每次 1 秒)..."
    declare -a STEAL_SAMPLES
    for i in $(seq 1 8); do
        R=$(steal_sample 1 "" "")
        [[ "$R" == "-1" ]] && R=0
        STEAL_SAMPLES[$i]=$R
        printf "  %2d: %.2f%%\n" "$i" "$R"
    done

    # 统计
    MAX_S=0; MIN_S=100; SUM_S=0
    for s in "${STEAL_SAMPLES[@]}"; do
        (( $(echo "$s > $MAX_S" | bc -l 2>/dev/null) )) && MAX_S=$s
        (( $(echo "$s < $MIN_S" | bc -l 2>/dev/null) )) && MIN_S=$s
        SUM_S=$(awk "BEGIN {printf \"%.2f\", $SUM_S + $s}")
    done
    AVG_S=$(awk "BEGIN {printf \"%.2f\", $SUM_S / 8}")
    JITTER=$(awk "BEGIN {printf \"%.2f\", $MAX_S - $MIN_S}")
    STDDEV=0
    for s in "${STEAL_SAMPLES[@]}"; do
        STDDEV=$(awk "BEGIN {printf \"%.2f\", $STDDEV + ($s - $AVG_S)^2}")
    done
    STDDEV=$(awk "BEGIN {printf \"%.2f\", sqrt($STDDEV / 8)}")

    echo ""
    label "平均 Steal:"     "${AVG_S}%"
    label "最大 Steal:"     "${MAX_S}%"
    label "最小 Steal:"     "${MIN_S}%"
    label "波动范围:"       "$(color_val $JITTER 8 20)%"
    label "标准差:"         "$(color_val $STDDEV 3 8)"

    # 4.5 邻居 VM 活动模式推断
    echo ""
    info "测试 5/5: 邻居 VM 活动模式推断..."

    # 模式分析:
    # 1. Steal 持续偏高 → 邻居 VM 持续高负载
    # 2. Steal 间歇性飙升 → 邻居 VM 周期性任务
    # 3. Steal 稳定低 → 邻居 VM 空闲或没有邻居
    # 4. 大波动 + 高标准差 → 多个邻居 VM 交替活动

    if (( $(echo "$AVG_S > 10.0" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$JITTER > 15.0" | bc -l 2>/dev/null || echo 0) )); then
            NEIGHBOR_PATTERN="多个邻居 VM 在高负载下争抢 CPU，且活动波动大"
            NEIGHBOR_CONFIDENCE="高"
            NEIGHBOR_COUNT_EST="≥3 (多个邻居)"
            add_risk 6 "Steal模式:多个邻居VM高负载争抢"
        else
            NEIGHBOR_PATTERN="有一个或多个邻居 VM 持续高负载运行"
            NEIGHBOR_CONFIDENCE="中-高"
            NEIGHBOR_COUNT_EST="1-3 个邻居"
            add_risk 4 "Steal模式:持续高负载，有邻居VM"
        fi
    elif (( $(echo "$AVG_S > 5.0" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$JITTER > 10.0" | bc -l 2>/dev/null || echo 0) )); then
            NEIGHBOR_PATTERN="邻居 VM 有间歇性活动（如定时任务）"
            NEIGHBOR_CONFIDENCE="中"
            NEIGHBOR_COUNT_EST="1-2 个邻居有活动"
            add_risk 3 "Steal模式:邻居间歇活动"
        else
            NEIGHBOR_PATTERN="可能有 1 个邻居 VM 在轻度活动"
            NEIGHBOR_CONFIDENCE="低"
            NEIGHBOR_COUNT_EST="0-1 个邻居"
            add_risk 2 "Steal模式:疑似邻居轻度活动"
        fi
    elif (( $(echo "$AVG_S > 2.0" | bc -l 2>/dev/null || echo 0) )); then
        NEIGHBOR_PATTERN="邻居活动不明显或只有极轻微争抢"
        NEIGHBOR_CONFIDENCE="低"
        NEIGHBOR_COUNT_EST="0-1 个邻居(空闲)"
        add_risk 1 "Steal模式:轻微争抢"
    else
        NEIGHBOR_PATTERN="无明显邻居 VM 活动迹象"
        NEIGHBOR_CONFIDENCE="低"
        NEIGHBOR_COUNT_EST="邻居可能空闲或 VM 较少"
    fi

    label "推断邻居活动:"   "${NEIGHBOR_PATTERN}"
    label "可信度:"         "${NEIGHBOR_CONFIDENCE}"
    label "估计邻居数量:"   "${NEIGHBOR_COUNT_EST}"

    # Steal 综合判定（用于超售评分）
    WORST_STEAL=$AVG_IDLE
    (( $(echo "$R_LOAD > $WORST_STEAL" | bc -l 2>/dev/null) )) && WORST_STEAL=$R_LOAD
    (( $(echo "$R_FULL > $WORST_STEAL" | bc -l 2>/dev/null) )) && WORST_STEAL=$R_FULL

    if (( $(echo "$WORST_STEAL > 30" | bc -l 2>/dev/null || echo 0) )); then
        bad "CPU Steal 极高(${WORST_STEAL}%)！宿主机严重超售"
        add_risk 15 "Steal=$WORST_STEAL%，严重超售"
    elif (( $(echo "$WORST_STEAL > 15" | bc -l 2>/dev/null || echo 0) )); then
        bad "CPU Steal 很高(${WORST_STEAL}%)，明显超售"
        add_risk 10 "Steal=$WORST_STEAL%，明显超售"
    elif (( $(echo "$WORST_STEAL > 8" | bc -l 2>/dev/null || echo 0) )); then
        warn "CPU Steal 偏高(${WORST_STEAL}%)，存在超售"
        add_risk 6 "Steal=$WORST_STEAL%，存在超售"
    elif (( $(echo "$WORST_STEAL > 3" | bc -l 2>/dev/null || echo 0) )); then
        add_risk 3 "Steal=$WORST_STEAL%"
    elif (( $(echo "$WORST_STEAL > 1" | bc -l 2>/dev/null || echo 0) )); then
        add_risk 1 "Steal=$WORST_STEAL%"
    fi
else
    warn "Steal Time 不可用，核心超售检测缺失"
    add_risk 15 "Steal Time 不可用"
    NEIGHBOR_PATTERN="无法通过 Steal 分析邻居（Steal 不可用）"
    NEIGHBOR_CONFIDENCE="N/A"
fi
add_max 3

# ============================================================
#  5. 邻居 VM 探测 — 网络扫描
# ============================================================
header "【第五步】邻居 VM 网络探测（ARP/网段扫描）"

info "检查宿主机虚拟网络环境..."
add_max 5

# 5.1 检查网络接口和网关
GW_IP=""
GW_IFACE=""
while IFS= read -r line; do
    if [[ "$line" =~ ^default ]]; then
        GW_IP=$(echo "$line" | awk '{print $2}')
        GW_IFACE=$(echo "$line" | awk '{print $NF}')
    fi
done < <(ip route show 2>/dev/null || route -n 2>/dev/null || true)

if [[ -n "$GW_IP" ]]; then
    label "默认网关:" "${GW_IP} (${GW_IFACE})"

    # 判断网关 IP 是否可能是宿主机
    GW_PRIVATE=false
    if echo "$GW_IP" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
        GW_PRIVATE=true
    fi

    if $GW_PRIVATE; then
        info "网关在内网段，可能是宿主机或虚拟路由器"

        # 获取本机 IP
        MY_IP=""
        MY_NETMASK=""
        if [[ -n "$GW_IFACE" ]]; then
            MY_IP=$(ip addr show "$GW_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
            MY_CIDR=$(ip addr show "$GW_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1 | cut -d/ -f2)
            if [[ -n "$MY_CIDR" ]]; then
                MY_NETMASK=$MY_CIDR
            fi
        fi
        [[ -z "$MY_IP" ]] && MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
        label "本机 IP:" "${MY_IP:-未知}"

        # 计算网段
        if [[ -n "$MY_IP" ]] && [[ -n "$MY_NETMASK" ]]; then
            NETWORK_SEGMENT=$(ip route 2>/dev/null | grep -v default | grep "$GW_IFACE" | grep -oP '[\d.]+/[\d]+' | head -1 || echo "")
            if [[ -z "$NETWORK_SEGMENT" ]]; then
                NETWORK_SEGMENT=$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')
            fi
            label "本机网段:" "${NETWORK_SEGMENT}"

            # ARP 扫描探测邻居
            echo ""
            info "扫描本网段活跃主机（发现邻居 VM）..."
            if check_cmd arp-scan; then
                ARP_OUT=$(arp-scan --local --interface="$GW_IFACE" --numeric --retry=2 2>/dev/null || true)
                if [[ -n "$ARP_OUT" ]]; then
                    HOST_COUNT=$(echo "$ARP_OUT" | grep -cP '^[\d.]+[\s]+[\w:]+' 2>/dev/null || echo 0)
                    GW_MAC=$(echo "$ARP_OUT" | grep "^$GW_IP" | awk '{print $2}' || echo "")

                    # 过滤掉自己和网关
                    NEIGHBOR_ARP=$(echo "$ARP_OUT" | grep -v "^$MY_IP" | grep -v "^$GW_IP" | grep -P '^[\d.]+[\s]+[\w:]+' || true)
                    NEIGHBOR_ARP_COUNT=$(echo "$NEIGHBOR_ARP" | grep -c . 2>/dev/null || echo 0)

                    if [[ "$NEIGHBOR_ARP_COUNT" -gt 0 ]]; then
                        NEIGHBOR_FOUND=true
                        NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + NEIGHBOR_ARP_COUNT))
                        warn "发现 ${NEIGHBOR_ARP_COUNT} 个网段邻居（可能是同宿主机的其他 VM）"
                        echo ""
                        sub "  邻居列表:"
                        echo "$NEIGHBOR_ARP" | while IFS= read -r line; do
                            NIP=$(echo "$line" | awk '{print $1}')
                            NMAC=$(echo "$line" | awk '{print $2}')
                            # 尝试解析主机名
                            NHOST=""
                            if check_cmd nmblookup; then
                                NHOST=$(nmblookup -A "$NIP" 2>/dev/null | grep "<00>" | grep -v "GROUP" | awk '{print $1}' | head -1 || echo "")
                            fi
                            if [[ -z "$NHOST" ]] && check_cmd host; then
                                NHOST=$(host "$NIP" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//' || echo "")
                            fi
                            if [[ -n "$NHOST" ]]; then
                                sub "    ${NIP}  (${NHOST})  [${NMAC}]"
                                NEIGHBOR_LIST="${NEIGHBOR_LIST}  ${NIP} (${NHOST})\n"
                            else
                                # KVM 默认 MAC 前缀: 52:54:00
                                if echo "$NMAC" | grep -qi "^52:54:00"; then
                                    sub "    ${NIP}  [${NMAC}] ← KVM 默认 MAC，很可能是邻居 VM"
                                    NEIGHBOR_LIST="${NEIGHBOR_LIST}  ${NIP} (KVM VM)\n"
                                else
                                    sub "    ${NIP}  [${NMAC}]"
                                    NEIGHBOR_LIST="${NEIGHBOR_LIST}  ${NIP}\n"
                                fi
                            fi
                        done
                        add_risk 3 "网段发现 ${NEIGHBOR_ARP_COUNT} 个邻居"
                    else
                        info "网段内只有本机和网关，未发现其他邻居"
                    fi

                    if [[ -n "$GW_MAC" ]]; then
                        label "网关 MAC:" "${GW_MAC}"
                        # 检查网关 MAC 厂商
                        if check_cmd grep; then
                            GW_OUI=$(echo "$GW_MAC" | tr -d ':' | cut -c1-6 | tr '[:lower:]' '[:upper:]')
                            label "网关 OUI:" "${GW_OUI}"
                        fi
                    fi
                fi
            elif check_cmd nmap; then
                info "使用 nmap 扫描网段..."
                NMAP_OUT=$(nmap -sn -n "$NETWORK_SEGMENT" --exclude "$MY_IP" 2>/dev/null || true)
                if [[ -n "$NMAP_OUT" ]]; then
                    HOSTS_UP=$(echo "$NMAP_OUT" | grep -c "Host is up" 2>/dev/null || echo 0)
                    NMAP_HOSTS=$(echo "$NMAP_OUT" | grep -oP 'Nmap scan report for [\d.]+' | grep -oP '[\d.]+' | grep -v "^$GW_IP$" | grep -v "^$MY_IP$" || true)
                    NMAP_COUNT=$(echo "$NMAP_HOSTS" | grep -c . 2>/dev/null || echo 0)

                    if [[ "$NMAP_COUNT" -gt 0 ]]; then
                        NEIGHBOR_FOUND=true
                        NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + NMAP_COUNT))
                        warn "nmap 发现 ${NMAP_COUNT} 个同网段主机（可能是邻居 VM）"
                        echo "$NMAP_HOSTS" | while IFS= read -r nip; do
                            [[ -z "$nip" ]] && continue
                            # 尝试解析 MAC
                            NMAC=$(arp -n "$nip" 2>/dev/null | grep -v "Address" | awk '{print $3}' || echo "")
                            if [[ -n "$NMAC" ]]; then
                                if echo "$NMAC" | grep -qi "^52:54:00"; then
                                    sub "  ${nip} [${NMAC}] ← KVM VM"
                                else
                                    sub "  ${nip} [${NMAC}]"
                                fi
                            else
                                sub "  ${nip}"
                            fi
                        done
                        add_risk 3 "nmap 发现 ${NMAP_COUNT} 个邻居"
                    fi
                fi
            else
                # 用 ping + ARP 简单扫描
                info "未安装 arp-scan/nmap，使用 ping 广播扫描..."
                NET_BASE=$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3}')
                LIVE_COUNT=0
                for i in $(seq 1 254); do
                    ping -c 1 -W 1 -n "${NET_BASE}.${i}" &>/dev/null && LIVE_COUNT=$((LIVE_COUNT + 1)) &
                done
                wait
                # 等待 ARP 表更新
                sleep 1

                ARP_ENTRIES=$(arp -n 2>/dev/null | grep -v "incomplete" | grep -v "^Address" | grep -v "${MY_IP}" | awk '{print $1, $3}' || true)
                ARP_COUNT=$(echo "$ARP_ENTRIES" | grep -c . 2>/dev/null || echo 0)
                if [[ "$ARP_COUNT" -gt 0 ]]; then
                    NEIGHBOR_FOUND=true
                    NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + ARP_COUNT))
                    warn "ARP 表发现 ${ARP_COUNT} 个潜在邻居"
                    echo "$ARP_ENTRIES" | while read -r nip nmac; do
                        if echo "$nmac" | grep -qi "^52:54:00"; then
                            sub "  ${nip} [${nmac}] ← KVM VM"
                        else
                            sub "  ${nip} [${nmac}]"
                        fi
                    done
                fi
            fi
        fi
    fi
else
    info "未找到默认网关，可能是容器或特殊网络配置"
fi

# 5.2 检查 virbr0 (libvirt NAT 网络)
echo ""
info "检查 libvirt 虚拟网络桥接..."
if ip link show virbr0 &>/dev/null; then
    VIRBR_IP=$(ip addr show virbr0 2>/dev/null | grep "inet " | awk '{print $2}')
    warn "存在 virbr0 网络桥 — 宿主机在使用 libvirt NAT 网络"
    label "virbr0 IP:" "${VIRBR_IP:-未知}"

    # virbr0 默认网段为 192.168.122.0/24
    # 扫描这个网段可能会找到其他 VM
    if [[ -z "$MY_IP" ]] || ! echo "$MY_IP" | grep -q "^192.168.122."; then
        info "virbr0 网段与当前 VM 不同网段，尝试扫描..."
        if check_cmd nmap; then
            VIRBR_SCAN=$(nmap -sn -n 192.168.122.0/24 2>/dev/null || true)
            VIRBR_HOSTS=$(echo "$VIRBR_SCAN" | grep -c "Host is up" 2>/dev/null || echo 0)
            if [[ "$VIRBR_HOSTS" -gt 1 ]]; then
                NEIGHBOR_FOUND=true
                NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + VIRBR_HOSTS - 1))
                warn "virbr0 网段发现 $((VIRBR_HOSTS - 1)) 个潜在邻居 VM！"
                add_risk 4 "virbr0 网段有邻居 VM"
            fi
        fi
    fi
fi

# 5.3 检查 libvirtd TCP 端口 (可能是远程管理接口)
echo ""
info "检查宿主机 libvirt 远程管理端口..."
if [[ -n "$GW_IP" ]]; then
    # 检测常见 libvirt 端口: 16509 (TCP), 16514 (TLS)
    for PORT in 16509 16514; do
        if timeout 2 bash -c "echo >/dev/tcp/${GW_IP}/${PORT}" 2>/dev/null; then
            warn "宿主机(${GW_IP}:${PORT}) libvirt 远程管理端口开放！"
            if [[ "$PORT" -eq 16509 ]]; then
                warn "TCP 端口 16509 开放 — libvirt 未加密远程访问"
                add_risk 5 "libvirt TCP 端口 16509 开放（安全风险）"
            elif [[ "$PORT" -eq 16514 ]]; then
                warn "TLS 端口 16514 开放 — libvirt TLS 远程访问"
            fi

            # 尝试连接并获取 VM 列表
            if check_cmd virsh && [[ -n "$GW_IP" ]]; then
                info "尝试通过 virsh 连接到宿主机..."
                VIRSH_OUT=$(virsh -c "qemu+tcp://${GW_IP}/system" list --all 2>/dev/null || true)
                if [[ -n "$VIRSH_OUT" ]] && ! echo "$VIRSH_OUT" | grep -qi "error\|failed\|refused"; then
                    bad "成功连接到宿主机 libvirtd！获取到 VM 列表！"
                    echo ""
                    echo "$VIRSH_OUT"
                    echo ""

                    # 统计 VM 数量
                    VM_TOTAL=$(echo "$VIRSH_OUT" | grep -cP '\s+\d+\s+' 2>/dev/null || echo 0)
                    VM_RUNNING=$(echo "$VIRSH_OUT" | grep -c "running" 2>/dev/null || echo 0)
                    BAD "宿主机上共有 ${VM_TOTAL} 个 VM，其中 ${VM_RUNNING} 个在运行！"
                    add_risk 10 "通过 libvirt 发现宿主机有 ${VM_TOTAL} 个 VM"
                    NEIGHBOR_FOUND=true
                    NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + VM_TOTAL))
                else
                    info "virsh 连接被拒绝（需要认证或 ACL）"
                fi
            fi
        fi
    done
fi

# 5.4 QEMU Guest Agent 探测
echo ""
info "检查 QEMU Guest Agent 通道..."
if check_cmd qemu-ga; then
    QGA_STATUS=$(systemctl is-active qemu-guest-agent 2>/dev/null || echo "unknown")
    label "QEMU Guest Agent:" "${QGA_STATUS}"
    if [[ "$QGA_STATUS" == "active" ]]; then
        info "QEMU Guest Agent 运行中（宿主机可通过此通道与 VM 通信）"
        # 尝试获取宿主机信息
        if check_cmd qemu-ga; then
            QGA_INFO=$(qemu-ga --blacklist='' 2>/dev/null || echo "受限")
            # 某些配置下 qemu-ga 可以提供宿主信息
            QGA_HOST=$(qemu-ga --blacklist guest-network-get-interfaces guest-network-query-routes 2>/dev/null || echo "")
        fi
    fi
fi

# ============================================================
#  6. 内存超售检测 (virtio_balloon + CommitLimit)
# ============================================================
header "【第六步】内存超售检测"

if [[ -f /proc/meminfo ]]; then
    MEM_TOTAL=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    MEM_AVAIL=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo)
    SWAP_TOTAL=$(awk '/SwapTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    COMMIT_LIMIT=$(awk '/CommitLimit/ {printf "%.0f", $2/1024}' /proc/meminfo)
    COMMITTED_AS=$(awk '/Committed_AS/ {printf "%.0f", $2/1024}' /proc/meminfo)

    label "总内存:"        "${MEM_TOTAL} MB"
    label "可用内存:"      "${MEM_AVAIL} MB"
    label "Swap 总量:"     "${SWAP_TOTAL} MB"
    add_max 8

    # 6.1 CommitLimit vs Committed_AS
    echo ""
    info "核心: 内存承诺分析 (Committed_AS vs CommitLimit)..."
    if [[ "$COMMIT_LIMIT" -gt 0 ]] && [[ "$COMMITTED_AS" -gt 0 ]]; then
        OC_RATIO=$(awk "BEGIN {printf \"%.2f\", $COMMITTED_AS / $COMMIT_LIMIT}" 2>/dev/null)
        label "CommitLimit:"   "${COMMIT_LIMIT} MB"
        label "Committed_AS:"  "${COMMITTED_AS} MB"
        label "承诺比率:"      "$(color_val $OC_RATIO 0.8 1.0)x"

        if (( $(echo "$COMMITTED_AS > $COMMIT_LIMIT" | bc -l 2>/dev/null) )); then
            bad "Committed_AS > CommitLimit！内存已超售"
            add_risk 8 "内存超售: Committed_AS(${COMMITTED_AS}) > CommitLimit(${COMMIT_LIMIT})"
        elif (( $(echo "$OC_RATIO > 0.8" | bc -l 2>/dev/null || echo 0) )); then
            warn "承诺比率 ${OC_RATIO}x，接近超售"
            add_risk 3 "承诺比率 ${OC_RATIO}x"
        else
            good "承诺比率正常"
        fi
    fi

    # 6.2 Balloon 驱动
    echo ""
    info "virtio_balloon 检测..."
    if lsmod 2>/dev/null | grep -qi "virtio_balloon"; then
        BALLOON_ACTIVE=true
        warn "virtio_balloon 已加载！"

        # 检查活动记录
        if dmesg 2>/dev/null | grep -i "balloon" | head -10 | grep -qi "inflate\|deflate\|update"; then
            warn "Balloon 驱动活跃（有充放气记录）— 内存正在被宿主机回收！"
            dmesg 2>/dev/null | grep -i "balloon" | tail -3 | while read -r line; do
                sub "${line}"
            done
            add_risk 7 "Balloon 活跃，内存正在被超售"
        else
            warn "Balloon 已加载但未见活动（可能近期未被触发）"
            add_risk 4 "Balloon 已加载"
        fi
    else
        good "未加载 virtio_balloon"
    fi

    # 6.3 Swap 分析
    echo ""
    info "Swap 使用分析..."
    if [[ "$SWAP_TOTAL" -gt 0 ]]; then
        SWAP_RATIO=$(awk "BEGIN {printf \"%.2f\", $SWAP_TOTAL / $MEM_TOTAL}" 2>/dev/null)
        label "Swap/内存:" "${SWAP_RATIO}x"
        if (( $(echo "$SWAP_TOTAL > $MEM_TOTAL * 2" | bc -l 2>/dev/null || echo 0) )); then
            warn "Swap > 内存×2，超售特征"
            add_risk 3 "Swap 远超内存"
        fi
    fi

    # 6.4 overcommit_memory
    if [[ -f /proc/sys/vm/overcommit_memory ]]; then
        OCM=$(cat /proc/sys/vm/overcommit_memory)
        if [[ "$OCM" -eq 1 ]]; then
            warn "overcommit_memory=1 (总是超售)"
            add_risk 3 "内核总是超售内存"
        fi
    fi
    add_max 3
else
    warn "无法读取内存信息"
    add_risk 8 "内存检测不可用"
fi

# ============================================================
#  7. 磁盘 IO 超售检测
# ============================================================
header "【第七步】磁盘 IO 超售检测"

add_max 5

if [[ -w /tmp ]]; then
    # 7.1 顺序写入
    info "顺序写入测试 (256MB)..."
    DD_OUT=$(dd if=/dev/zero of=/tmp/.io_seq bs=1M count=256 conv=fdatasync 2>&1)
    DD_TIME=$(echo "$DD_OUT" | grep -oP '[\d.]+(?= s)' | head -1)
    DD_SPEED=$(echo "$DD_OUT" | grep -oP '[\d.]+(?= MB/s)' | head -1)

    if [[ -n "$DD_TIME" ]]; then
        label "顺序写入:" "$(color_val ${DD_SPEED:-0} 50 20) MB/s (${DD_TIME}s)"
        if (( $(echo "$DD_TIME > 8.0" | bc -l 2>/dev/null || echo 0) )); then
            add_risk 5 "顺序写入 ${DD_TIME}s，IO 严重超售"
        elif (( $(echo "$DD_TIME > 3.0" | bc -l 2>/dev/null || echo 0) )); then
            add_risk 3 "顺序写入 ${DD_TIME}s，IO 争抢"
        fi
    fi

    # 7.2 4K 随机写入 (IOPS)
    echo ""
    info "4K 随机写入 (IOPS 测试)..."
    DD_RAND=$(dd if=/dev/zero of=/tmp/.io_rand bs=4k count=25000 conv=fdatasync 2>&1)
    RAND_TIME=$(echo "$DD_RAND" | grep -oP '[\d.]+(?= s)' | head -1)

    if [[ -n "$RAND_TIME" ]] && (( $(echo "$RAND_TIME > 0" | bc -l 2>/dev/null) )); then
        IOPS=$(awk "BEGIN {printf \"%.0f\", 25000 / $RAND_TIME}" 2>/dev/null)
        label "IOPS:" "$(color_val $IOPS 500 100)"

        if [[ "$IOPS" -lt 100 ]]; then
            bad "IOPS 极低(${IOPS})，磁盘严重超售或使用机械盘"
            add_risk 5 "IOPS=$IOPS，严重超售"
        elif [[ "$IOPS" -lt 500 ]]; then
            warn "IOPS 偏低(${IOPS})，磁盘争抢"
            add_risk 3 "IOPS=$IOPS，争抢"
        elif [[ "$IOPS" -lt 2000 ]]; then
            info "IOPS 尚可(${IOPS})"
        else
            good "IOPS 良好(${IOPS})"
        fi
    fi

    rm -f /tmp/.io_seq /tmp/.io_rand 2>/dev/null
fi

# ============================================================
#  8. CPU 扩展效率测试
# ============================================================
header "【第八步】CPU 扩展效率测试"

if check_cmd sysbench; then
    info "sysbench CPU 基准测试（评估 vCPU 扩展性）..."
    add_max 5

    SINGLE=$(sysbench cpu --cpu-max-prime=20000 --threads=1 run 2>/dev/null || true)
    S_EPS=$(echo "$SINGLE" | grep "events per second" | grep -oP '[\d.]+' | head -1)

    if [[ -n "$S_EPS" ]]; then
        label "单线程 EPS:" "${S_EPS}"

        MULTI=$(sysbench cpu --cpu-max-prime=20000 --threads=$VCPU_COUNT run 2>/dev/null || true)
        M_EPS=$(echo "$MULTI" | grep "events per second" | grep -oP '[\d.]+' | head -1)

        if [[ -n "$M_EPS" ]] && [[ "$VCPU_COUNT" -gt 0 ]]; then
            label "多线程 EPS:" "${M_EPS}"
            SCALING=$(awk "BEGIN {printf \"%.2f\", $M_EPS / ($S_EPS * $VCPU_COUNT)}" 2>/dev/null)
            label "扩展效率:" "$(color_val $SCALING 0.6 0.3)"

            if (( $(echo "$SCALING < 0.3" | bc -l 2>/dev/null || echo 0) )); then
                bad "扩展效率仅 ${SCALING}，vCPU 严重争抢物理核心"
                add_risk 5 "CPU扩展效率=${SCALING}，严重争抢"
            elif (( $(echo "$SCALING < 0.6" | bc -l 2>/dev/null || echo 0) )); then
                warn "扩展效率 ${SCALING}，vCPU 有争抢"
                add_risk 3 "CPU扩展效率=${SCALING}，有争抢"
            elif (( $(echo "$SCALING < 0.85" | bc -l 2>/dev/null || echo 0) )); then
                info "扩展效率 ${SCALING}"
            else
                good "扩展效率 ${SCALING}"
            fi
        fi
    fi
else
    info "未安装 sysbench，跳过 CPU 扩展效率测试"
    info "安装: apt install sysbench / yum install sysbench"
fi

# ============================================================
#  9. 综合结果
# ============================================================
header "【综合结论】超售检测 & 邻居 VM 探测结果"

# 确保分母不为 0
[[ "$MAX_SCORE" -eq 0 ]] && MAX_SCORE=100
SCORE_PCT=$(awk "BEGIN {printf \"%d\", ($RISK_SCORE * 100) / $MAX_SCORE}" 2>/dev/null)
[[ -z "$SCORE_PCT" ]] && SCORE_PCT=0

echo ""
echo -e "  ${BOLD}━━ 超售风险评估 ━━${NC}"
label "虚拟化类型:"     "KVM"
label "风险总分:"       "${RISK_SCORE} / ${MAX_SCORE}"
label "超售风险指数:"   "${SCORE_PCT}%"
echo ""

if [[ "$SCORE_PCT" -le 10 ]]; then
    GRADE="${GREEN}A${NC}"
    DESC="几乎无超售迹象，宿主机资源配置良好"
elif [[ "$SCORE_PCT" -le 25 ]]; then
    GRADE="${GREEN}B${NC}"
    DESC="轻度超售，日常使用影响不大"
elif [[ "$SCORE_PCT" -le 45 ]]; then
    GRADE="${YELLOW}C${NC}"
    DESC="中度超售，高峰期可能性能下降"
elif [[ "$SCORE_PCT" -le 65 ]]; then
    GRADE="${RED}D${NC}"
    DESC="严重超售，建议联系服务商或迁移"
else
    GRADE="${RED}F${NC}"
    DESC="极度超售！强烈建议更换"
fi
label "超售等级:"       "${GRADE}"
label "评估意见:"       "${DESC}"

echo ""
echo -e "  ${BOLD}━━ 邻居 VM 探测结果 ━━${NC}"

if $NEIGHBOR_FOUND; then
    bad "检测到宿主机上存在其他 VM 的活动迹象！"
    label "推测邻居 VM 数:"  "${NEIGHBOR_COUNT}"
    label "活动模式:"        "${NEIGHBOR_PATTERN}"
    label "可信度:"          "${NEIGHBOR_CONFIDENCE}"
    if [[ -n "$NEIGHBOR_LIST" ]]; then
        echo -e "  ${BOLD}邻居地址列表:${NC}"
        echo -e "$NEIGHBOR_LIST"
    fi
else
    if [[ "$NEIGHBOR_CONFIDENCE" == "N/A" ]]; then
        info "无法通过 Steal Time 检测邻居（Steal 不可用）"
    else
        info "当前未检测到明确的邻居 VM 活动迹象"
        label "活动模式:"   "${NEIGHBOR_PATTERN-未检测}"
    fi
    info "注意: 无检测结果 ≠ 没有邻居，可能是邻居空闲或网络隔离"
fi

echo ""
echo -e "  ${BOLD}━━ 关键风险项 ── ${NC}"
if [[ ${#REPORT_LINES[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}未检测到明显超售迹象${NC}"
else
    IFS=$'\n'
    SORTED=($(sort -t'+' -k2 -rn <<< "${REPORT_LINES[*]}"))
    unset IFS
    for line in "${SORTED[@]}"; do
        W=$(echo "$line" | grep -oP '(?<=\+)\d+' | head -1)
        D=$(echo "$line" | sed 's/^+[0-9]*://')
        if [[ "$W" -ge 6 ]]; then
            echo -e "  ${RED}[严重]${NC} ${D} (+${W})"
        elif [[ "$W" -ge 3 ]]; then
            echo -e "  ${YELLOW}[中等]${NC} ${D} (+${W})"
        else
            echo -e "  ${NC}[轻微]${NC} ${D} (+${W})"
        fi
    done
fi

echo ""
echo -e "${MAGENTA}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║  检测完毕                                    ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}结果解读与建议:${NC}"
echo -e "  ──────────────────────────────────────────────"
echo -e "  • CPU Steal > 10% = 宿主机 CPU 超售，邻居在抢资源"
echo -e "  • L3 Cache 推算物理核心数，vCPU/核心比 > 2 = 超售"
echo -e "  • Balloon 活跃 = 内存被宿主机回收，是内存超售的铁证"
echo -e "  • Committed_AS > CommitLimit = 内核承认内存超售"
echo -e "  • 网段发现多个主机 = 可能是邻居 VM"
echo -e "  • libvirt 端口 16509 开放 = 可直接查 VM 列表"
echo -e "  • 邻居检测是旁路推断，不能替代宿主机直接查看"
echo -e ""
echo -e "  ${YELLOW}建议: 如果担心合伙人超开，可以把检测结果截图${NC}"
echo -e "  ${YELLOW}作为证据与对方沟通。严重超售 (D/F) 建议投诉或迁移。${NC}"
echo ""
