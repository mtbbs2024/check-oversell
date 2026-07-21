#!/bin/bash
# ============================================================
#  KVM 宿主机深度穿透检测脚本 v4.0
#  从虚拟机内部，通过 KVM 暴露信息 + 侧信道分析
#  推断宿主机状态与邻居 VM 情况
#
#  技术边界声明:
#  ──────────────────────────────────────────────────
#  KVM 安全隔离阻止 VM 直接访问宿主信息（/proc、
#  virsh list、宿主进程、宿主文件系统）。
#  本脚本仅使用 KVM 设计允许暴露的接口 + 时序/
#  网络/缓存侧信道分析，不包含 VM 逃逸漏洞利用。
#
#  如果宿主机无意中开放了管理接口（如 libvirt TCP
#  16509 端口未认证），脚本会尝试连接获取精确数据。
# ──────────────────────────────────────────────────
#  宿主机暴露的信息源:
#    1. CPUID 0x40000000+ leaves (KVM 版本、特性)
#    2. DMI/SMBIOS (产品名、BIOS、主板)
#    3. /dev/kvm ioctl (KVM API 版本)
#    4. CPU Steal Time (调度竞争度量)
#    5. 时钟源 (kvm-clock PV 时钟)
#    6. virtio 设备信息
#    7. L3 Cache 拓扑 (共享缓存推断物理核心)
#    8. 网络拓扑 (ARP/路由/端口扫描)
#    9. 串口/QEMU Monitor (可能暴露)
#    10. 性能计数器 (PMU)
# ============================================================

set +e
set -o pipefail 2>/dev/null || true

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
NEIGHBOR_COUNT=0
NEIGHBOR_LIST=""
HOST_INFO_FOUND=false

# ---------- 辅助函数 ----------
info()    { echo -e "${CYAN}[信息]${NC} $1"; }
good()    { echo -e "${GREEN}[通过]${NC} $1"; }
warn()    { echo -e "${YELLOW}[警告]${NC} $1"; }
bad()     { echo -e "${RED}[异常]${NC} $1"; }
found()   { echo -e "${GREEN}[发现]${NC} $1"; }
header()  { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }
label()   { printf "  %-30s %s\n" "$1" "$2"; }
sub()     { echo -e "  ${DIM}$1${NC}"; }

add_risk() { local w=$1 d=$2; RISK_SCORE=$((RISK_SCORE + w)); REPORT_LINES+=("+${w}:${d}"); }
add_max()  { MAX_SCORE=$((MAX_SCORE + $1)); }

check_cmd() { command -v "$1" &>/dev/null; }

color_val() {
    local val=$1 w=$2 b=$3
    (( $(echo "$val >= $b" | bc -l 2>/dev/null || echo 0) )) && echo -e "${RED}${val}${NC}" && return
    (( $(echo "$val >= $w" | bc -l 2>/dev/null || echo 0) )) && echo -e "${YELLOW}${val}${NC}" && return
    echo -e "${GREEN}${val}${NC}"
}

# ---------- 检查 root ----------
if [[ $EUID -ne 0 ]]; then
    warn "建议以 root 运行以获得完整检测结果"
fi

# ============================================================
echo -e ""
echo -e "${MAGENTA}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║   KVM 宿主机深度穿透检测脚本 v4.0                    ║${NC}"
echo -e "${MAGENTA}║   从 VM 内部 → 推断宿主机状态                       ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}KVM 安全隔离设计阻止 VM 直接访问宿主信息。${NC}"
echo -e "  ${DIM}本脚本通过 KVM 设计允许暴露的接口（CPUID leaves、DMI、${NC}"
echo -e "  ${DIM}Steal Time、L3 Cache、/dev/kvm、网络拓扑等）进行分析。${NC}"
echo -e "  ${DIM}如果宿主机开放了 libvirt TCP 端口，可获取精确 VM 列表。${NC}"
echo ""
echo -e "  ${YELLOW}检测 ≠ 逃逸。真正的 VM 逃逸需要安全漏洞（CVE），${NC}"
echo -e "  ${YELLOW}不存在通用的"突破"脚本。${NC}"
echo ""

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

# /proc/cpuinfo 检测
if grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null; then
    if grep -qi "KVM\|QEMU" /proc/cpuinfo 2>/dev/null; then
        IS_KVM=true
    fi
fi

# /sys/hypervisor 检测
if [[ -d /sys/hypervisor ]] && [[ -f /sys/hypervisor/type ]]; then
    HVTYPE=$(cat /sys/hypervisor/type 2>/dev/null)
    [[ "$HVTYPE" == "kvm" ]] && IS_KVM=true
fi

# /dev/kvm 检测
if [[ -c /dev/kvm ]]; then
    IS_KVM=true
    found "/dev/kvm 设备存在 — 确认 KVM 环境"
fi

if ! $IS_KVM; then
    warn "未检测到 KVM 环境！当前: ${VIRT_TYPE}"
    warn "部分检测项不可用，但会尽量执行"
else
    good "确认 KVM 虚拟化环境 (${VIRT_TYPE})"
fi
add_max 5

# ============================================================
#  2. CPUID leaves — KVM→VM 接口 (宿主机主动暴露的信息)
# ============================================================
header "【第二步】KVM CPUID Leaves（宿主机主动暴露的信息）"

info "KVM 通过 CPUID 0x40000000+ leaves 向 VM 暴露版本、特性等信息..."
echo ""

if [[ -c /dev/kvm ]]; then
    info "尝试通过 /dev/kvm ioctl 读取 KVM 版本..."
    # 用 grep 在 dmesg 中找 KVM 版本信息
    if dmesg 2>/dev/null | grep -i "kvm" | grep -i "version" | head -3; then
        :
    fi
fi

# 2.1 cpuid 工具解析
if check_cmd cpuid; then
    # leaf 0x40000000: KVM 签名
    for leaf in 0x40000000 0x40000001 0x40000002 0x40000003; do
        CPUID_OUT=$(cpuid -1 -l "$leaf" 2>/dev/null || true)
        [[ -z "$CPUID_OUT" ]] && continue

        EAX_HEX=$(echo "$CPUID_OUT" | grep -i "eax" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "0x0")
        EBX_HEX=$(echo "$CPUID_OUT" | grep -i "ebx" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "0x0")
        ECX_HEX=$(echo "$CPUID_OUT" | grep -i "ecx" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "0x0")
        EDX_HEX=$(echo "$CPUID_OUT" | grep -i "edx" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "0x0")

        case $leaf in
            0x40000000)
                EAX_DEC=$((EAX_HEX))
                label "最大 KVM CPUID 叶子:" "0x$(printf '%x' "$EAX_DEC") ($((EAX_DEC - 0x40000000)) 个子叶子)"
                HOST_INFO_FOUND=true
                ;;
            0x40000001)
                KVM_VER=$((EAX_HEX))
                KVM_MAJOR=$(( (KVM_VER >> 16) & 0xFF ))
                KVM_MINOR=$(( (KVM_VER >> 8) & 0xFF ))
                KVM_PATCH=$(( KVM_VER & 0xFF ))
                label "KVM 内核接口版本:" "${KVM_MAJOR}.${KVM_MINOR}.${KVM_PATCH}"

                # KVM 特性标志
                EBX_DEC=$((EBX_HEX))
                label "KVM 特性标志:" "0x$(printf '%x' "$EBX_DEC")"
                LABEL=""
                (( EBX_DEC & 1 )) && LABEL+="时钟源, "
                (( EBX_DEC & 2 )) && LABEL+="时钟源v2, "
                (( EBX_DEC & 4 )) && LABEL+="PV EOI, "
                (( EBX_DEC & 8 )) && LABEL+="PV UNHALT, "
                (( EBX_DEC & 16 )) && LABEL+="PF STEAL, "
                (( EBX_DEC & 64 )) && LABEL+="ASYNC PF, "
                (( EBX_DEC & 128 )) && LABEL+="STEAL CLOCK, "
                (( EBX_DEC & 256 )) && LABEL+="PV TLB, "
                (( EBX_DEC & 1024 )) && LABEL+="PV MSR, "
                (( EBX_DEC & 4096 )) && LABEL+="HWPF, "
                [[ -n "$LABEL" ]] && sub "特性: ${LABEL%, }"

                HOST_INFO_FOUND=true
                label "" ""
                ;;
            0x40000002)
                EAX_DEC=$((EAX_HEX))
                label "PV 特性 (EAX):" "0x$(printf '%x' "$EAX_DEC")"
                [[ $((EAX_DEC & 1)) -ne 0 ]] && sub "支持 PV EOI (Edge-Triggered 中断加速)"
                HOST_INFO_FOUND=true
                ;;
            0x40000003)
                EAX_DEC=$((EAX_HEX))
                label "PV 时钟信息:" "tz=${EAX_DEC}"
                HOST_INFO_FOUND=true
                ;;
        esac
    done

    # 第 2 步: 尝试 0x40000100+ (Hyper-V 兼容)
    HV_CPUID=$(cpuid -1 -l 0x40000100 2>/dev/null || true)
    if [[ -n "$HV_CPUID" ]]; then
        HV_EAX=$(echo "$HV_CPUID" | grep -i "eax" | head -1 | grep -oP '0x[0-9a-fA-F]+' || echo "")
        if [[ -n "$HV_EAX" ]]; then
            found "检测到 Hyper-V enlightenment CPUID leaves"
            label "Hyper-V 接口:" "存在 (Windows 兼容层)"
        fi
    fi
else
    info "未安装 cpuid，可通过以下方式安装:"
    info "  apt install cpuid | yum install cpuid"
    info "  (不装亦可，会跳过部分检测)"
fi
add_max 5

# ============================================================
#  3. DMI/SMBIOS — 宿主机 BIOS/硬件信息
# ============================================================
header "【第三步】DMI/SMBIOS 宿主机硬件信息"

info "DMI 信息由 QEMU 固件模拟，暴露宿主机配置..."
echo ""

DMI_FIELDS=(
    "product_name:产品名"
    "product_version:产品版本"
    "product_uuid:产品 UUID"
    "sys_vendor:系统厂商"
    "bios_vendor:BIOS 厂商"
    "bios_version:BIOS 版本"
    "bios_date:BIOS 日期"
    "board_name:主板名"
    "board_vendor:主板厂商"
    "board_version:主板版本"
    "chassis_asset_tag:机箱标签"
)

for entry in "${DMI_FIELDS[@]}"; do
    FILE="${entry%%:*}"
    DESC="${entry#*:}"
    if [[ -f "/sys/class/dmi/id/${FILE}" ]]; then
        VAL=$(cat "/sys/class/dmi/id/${FILE}" 2>/dev/null)
        if [[ -n "$VAL" ]] && [[ "$VAL" != "Not Specified" ]] && [[ "$VAL" != "To be filled by O.E.M." ]]; then
            label "DMI ${DESC}:" "${VAL:0:80}"
            HOST_INFO_FOUND=true
        fi
    fi
done

# 通过 dmidecode (root 权限)
if [[ $EUID -eq 0 ]] && check_cmd dmidecode; then
    echo ""
    info "dmidecode 详细信息..."
    DMITYPE0=$(dmidecode -t 0 2>/dev/null | grep -E "Vendor|Version|Release" | head -3)
    if [[ -n "$DMITYPE0" ]]; then
        echo "$DMITYPE0" | while IFS= read -r line; do
            sub "${line}"
        done
        HOST_INFO_FOUND=true
    fi
    DMITYPE1=$(dmidecode -t 1 2>/dev/null | grep -E "Manufacturer|Product|Serial|UUID" | head -5)
    if [[ -n "$DMITYPE1" ]]; then
        echo "$DMITYPE1" | while IFS= read -r line; do
            sub "${line}"
        done
        HOST_INFO_FOUND=true
    fi
fi
add_max 3

# ============================================================
#  4. /dev/kvm 深度探测
# ============================================================
header "【第四步】/dev/kvm 接口深度探测"

info "/dev/kvm 是 KVM 暴露给 VM 的控制接口..."
echo ""

if [[ -c /dev/kvm ]]; then
    KVM_PERM=$(ls -la /dev/kvm 2>/dev/null | awk '{print $1, $3, $4}')
    label "/dev/kvm 权限:" "${KVM_PERM:-不可读}"

    # 尝试用 dd + hexdump 读取 KVM 版本字符串
    # KVM 在 /sys/module/kvm/ 下暴露一些信息
    for kvm_mod in kvm kvm_intel kvm_amd; do
        if [[ -d "/sys/module/${kvm_mod}" ]]; then
            VERSION=$(cat "/sys/module/${kvm_mod}/version" 2>/dev/null || echo "")
            if [[ -n "$VERSION" ]] && [[ "$VERSION" != "(not set)" ]]; then
                label "KVM 模块版本 (${kvm_mod}):" "${VERSION}"
                HOST_INFO_FOUND=true
            fi

            SRCVERSION=$(cat "/sys/module/${kvm_mod}/srcversion" 2>/dev/null || echo "")
            if [[ -n "$SRCVERSION" ]] && [[ "$SRCVERSION" != "(not set)" ]]; then
                label "KVM 源码版本:" "${SRCVERSION:0:20}"
                HOST_INFO_FOUND=true
            fi

            # 参数信息
            for param in /sys/module/${kvm_mod}/parameters/*; do
                if [[ -f "$param" ]]; then
                    PNAME=$(basename "$param")
                    PVAL=$(cat "$param" 2>/dev/null || echo "")
                    case "$PNAME" in
                        nested)    [[ "$PVAL" != "N" ]] && sub "支持嵌套虚拟化 (nested=$PVAL)" ;;
                        enable_vmware|enable_shadow_vmcs) sub "VMX 特性: ${PNAME}=${PVAL}" ;;
                        ignore_msrs|report_ignored_msrs) sub "MSR 策略: ${PNAME}=${PVAL}" ;;
                    esac
                fi
            done 2>/dev/null
        fi
    done

    # 尝试通过 Python 或 C 程序读取 KVM API 版本
    if check_cmd python3; then
        PY_KVM=$(python3 -c "
import os, struct
try:
    fd = os.open('/dev/kvm', os.O_RDWR)
    # KVM_GET_API_VERSION = 0xAE00
    import fcntl
    KVM_GET_API_VERSION = 0xAE00
    ver = struct.unpack('i', fcntl.ioctl(fd, KVM_GET_API_VERSION, struct.pack('i', 0)))[0]
    os.close(fd)
    print(ver)
except Exception as e:
    print('err:' + str(e))
" 2>/dev/null || true)
        if [[ -n "$PY_KVM" ]] && ! echo "$PY_KVM" | grep -q "^err:"; then
            label "KVM API 版本 (ioctl):" "${PY_KVM}"
            HOST_INFO_FOUND=true
        fi
    fi
else
    warn "/dev/kvm 不存在 — KVM 模块可能未加载"
fi
add_max 3

# ============================================================
#  5. L3 Cache → 推断宿主机物理核心 (关键穿透技术)
# ============================================================
header "【第五步】L3 Cache 拓扑 → 推断宿主机物理核心数"

VCPU_COUNT=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | sed 's/.*:\s*//')
SOCKETS=$(lscpu 2>/dev/null | grep "Socket(s)" | awk '{print $NF}')
[[ -z "$SOCKETS" ]] && SOCKETS=1

label "vCPU 数:"   "${VCPU_COUNT}"
label "CPU 型号:"  "${CPU_MODEL:-未知}"
label "Socket 数:" "${SOCKETS}"

# 读取 L3 Cache
L3_SIZE=""
for cid in /sys/devices/system/cpu/cpu0/cache/index*/; do
    [[ -f "${cid}type" ]] && [[ "$(cat "${cid}type" 2>/dev/null)" == "Unified" ]] && L3_SIZE=$(cat "${cid}size" 2>/dev/null) && break
done
[[ -z "$L3_SIZE" ]] && L3_SIZE=$(lscpu 2>/dev/null | grep "L3" | awk '{print $NF}')

L3_NUM=$(echo "$L3_SIZE" | grep -oP '[\d.]+' | head -1)

if [[ -n "$L3_NUM" ]]; then
    label "L3 Cache:" "${L3_NUM} MB"
    add_max 8

    # 根据架构推算
    if echo "$CPU_MODEL" | grep -qi "Intel"; then
        PHYSICAL_EST=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 1.375}" 2>/dev/null)
        [[ "$PHYSICAL_EST" -lt 2 ]] && PHYSICAL_EST=2
        label "估算宿主机物理核心:" "${PHYSICAL_EST} 核 (Intel ~1.375MB L3/核)"
    elif echo "$CPU_MODEL" | grep -qi "AMD\|Hygon"; then
        CCD_COUNT=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 32}" 2>/dev/null)
        [[ "$CCD_COUNT" -lt 1 ]] && CCD_COUNT=1
        PHYSICAL_EST=$((CCD_COUNT * 8))
        label "估算 CCD 数:" "${CCD_COUNT}"
        label "估算宿主机物理核心:" "${PHYSICAL_EST} 核 (AMD 8核/CCD)"
    else
        PHYSICAL_EST=$(awk "BEGIN {printf \"%.0f\", $L3_NUM / 1.5}" 2>/dev/null)
        [[ "$PHYSICAL_EST" -lt 2 ]] && PHYSICAL_EST=2
        label "估算宿主机物理核心:" "${PHYSICAL_EST} 核 (通用)"
    fi

    # 核心对比
    if [[ "$PHYSICAL_EST" -gt 0 ]] && [[ "$VCPU_COUNT" -gt 0 ]]; then
        RATIO=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / $PHYSICAL_EST}" 2>/dev/null)
        label "vCPU/物理核心比:" "$(color_val "$RATIO" 2 4)x"
        RATIO_HT=$(awk "BEGIN {printf \"%.1f\", $VCPU_COUNT / ($PHYSICAL_EST * 2)}" 2>/dev/null)
        label "vCPU/物理线程比:" "$(color_val "$RATIO_HT" 1 1.5)x"

        if (( $(echo "$RATIO > 4.0" | bc -l 2>/dev/null || echo 0) )); then
            bad "vCPU/核心=${RATIO}x！严重超售（正常上限 2x）"
            add_risk 8 "L3推算: vCPU/核心=${RATIO}x，严重超售"
        elif (( $(echo "$RATIO > 2.0" | bc -l 2>/dev/null || echo 0) )); then
            bad "vCPU/核心=${RATIO}x！超过超线程上限 2x，确实超售"
            add_risk 6 "L3推算: vCPU/核心=${RATIO}x，超售"
        elif (( $(echo "$RATIO > 1.0" | bc -l 2>/dev/null || echo 0) )); then
            warn "vCPU/核心=${RATIO}x，存在超售"
            add_risk 3 "L3推算: vCPU/核心=${RATIO}x"
        else
            good "vCPU 数在物理核心范围内"
        fi
    fi
else
    warn "无法读取 L3 Cache 大小"
fi
add_max 3

# ============================================================
#  6. CPU Steal Time 深度 + 邻居模式分析
# ============================================================
header "【第六步】CPU Steal Time → 邻居 VM 活动分析"

steal_avail=false
if [[ -f /proc/stat ]]; then
    COLS=$(awk '/^cpu / {print NF-1}' /proc/stat 2>/dev/null)
    [[ "$COLS" -ge 8 ]] && steal_avail=true
fi

if $steal_avail; then
    info "Steal Time 时序分析（检测 vCPU 调度竞争，判断邻居 VM 活动）..."
    echo ""
    add_max 15

    do_sample() {
        local sec=$1
        read s1 t1 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)
        sleep "$sec"
        read s2 t2 <<< $(awk '/^cpu / {print $8, $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat 2>/dev/null)
        if [[ -n "$s1" && -n "$s2" && -n "$t1" && -n "$t2" ]] && [[ $((t2 - t1)) -gt 0 ]]; then
            awk "BEGIN {printf \"%.2f\", (($s2 - $s1) / ($t2 - $t1)) * 100}"
        else
            echo "0"
        fi
    }

    # 空闲态采样
    info "采样 1: 空闲状态 Steal (3 次取平均)..."
    total=0; valid=0
    for i in 1 2 3; do
        r=$(do_sample 1)
        total=$(awk "BEGIN {printf \"%.2f\", $total + $r}")
        valid=$((valid + 1))
        sleep 0.3
    done
    idle_avg=$(awk "BEGIN {printf \"%.2f\", $total / $valid}")
    label "空闲 Steal:" "$(color_val "$idle_avg" 3 10)%"

    # 满载采样
    info "采样 2: 全 vCPU 满载 Steal..."
    pids=""
    for ((i=0; i<VCPU_COUNT; i++)); do
        sha256sum /dev/zero >/dev/null 2>&1 &
        pids="$pids $!"
    done
    sleep 1
    load_avg=$(do_sample 4)
    for pid in $pids; do kill "$pid" 2>/dev/null || true; done 2>/dev/null
    label "满载 Steal:" "$(color_val "$load_avg" 8 20)%"

    # 快速时序采样 (邻居活动分析)
    echo ""
    info "采样 3: Steal 时序模式（8 次×1 秒 — 检测邻居 VM 活动节律）..."
    declare -a SAMPLES
    for i in $(seq 1 8); do
        SAMPLES[$i]=$(do_sample 1)
    done

    sum_s=0; max_s=0; min_s=100
    for ((i=1; i<=8; i++)); do
        r=${SAMPLES[$i]}
        printf "  %2ds: %.2f%%\n" "$i" "$r"
        sum_s=$(awk "BEGIN {printf \"%.2f\", $sum_s + $r}")
        (( $(echo "$r > $max_s" | bc -l 2>/dev/null) )) && max_s=$r
        (( $(echo "$r < $min_s" | bc -l 2>/dev/null) )) && min_s=$r
    done
    avg_s=$(awk "BEGIN {printf \"%.2f\", $sum_s / 8}")
    jitter=$(awk "BEGIN {printf \"%.2f\", $max_s - $min_s}")

    # 标准差
    stdev=0
    for ((i=1; i<=8; i++)); do
        stdev=$(awk "BEGIN {printf \"%.2f\", $stdev + (${SAMPLES[$i]} - $avg_s)^2}")
    done
    stdev=$(awk "BEGIN {printf \"%.2f\", sqrt($stdev / 8)}")

    echo ""
    label "平均:"    "${avg_s}%"
    label "波动:"    "$(color_val "$jitter" 8 20)%"
    label "标准差:"  "$(color_val "$stdev" 3 7)"

    # ---- 邻居活动模式推断 ----
    echo ""
    info "邻居 VM 活动模式推断..."
    echo ""

    if (( $(echo "$avg_s > 15.0" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$jitter > 15.0" | bc -l 2>/dev/null || echo 0) )); then
            bad "多个邻居 VM 在高负载下争抢 CPU"
            add_risk 7 "Steal模式: 多个邻居VM高负载争抢"
            NEIGHBOR_COUNT=3
        else
            bad "至少一个邻居 VM 持续高负载"
            add_risk 5 "Steal模式: 邻居持续高负载"
            NEIGHBOR_COUNT=2
        fi
    elif (( $(echo "$avg_s > 8.0" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$jitter > 12.0" | bc -l 2>/dev/null || echo 0) )); then
            warn "邻居 VM 间歇性活动（定时任务/周期性负载）"
            add_risk 4 "Steal模式: 邻居间歇活动"
            NEIGHBOR_COUNT=2
        else
            warn "可能有 1-2 个邻居 VM 在活动"
            add_risk 3 "Steal模式: 邻居轻度活动"
            NEIGHBOR_COUNT=1
        fi
    elif (( $(echo "$avg_s > 3.0" | bc -l 2>/dev/null || echo 0) )); then
        info "Steal 略高，可能有轻度争抢"
        add_risk 2 "Steal模式: 轻度争抢"
        NEIGHBOR_COUNT=0
    else
        good "Steal 极低，无明显邻居活动"
        NEIGHBOR_COUNT=0
    fi

    # Steal 超售评分
    worst=$idle_avg
    (( $(echo "$load_avg > $worst" | bc -l 2>/dev/null) )) && worst=$load_avg
    (( $(echo "$avg_s > $worst" | bc -l 2>/dev/null) )) && worst=$avg_s

    if (( $(echo "$worst > 30" | bc -l 2>/dev/null || echo 0) )); then
        add_risk 12 "Steal=$worst%，严重超售"
    elif (( $(echo "$worst > 15" | bc -l 2>/dev/null || echo 0) )); then
        add_risk 8 "Steal=$worst%，明显超售"
    elif (( $(echo "$worst > 8" | bc -l 2>/dev/null || echo 0) )); then
        add_risk 5 "Steal=$worst%，超售"
    elif (( $(echo "$worst > 3" | bc -l 2>/dev/null || echo 0) )); then
        add_risk 2 "Steal=$worst%"
    fi
else
    warn "Steal Time 不可用"
    add_risk 15 "Steal 不可用"
fi
add_max 3

# ============================================================
#  7. 网络穿透 — 寻找宿主机/邻居
# ============================================================
header "【第七步】网络探测 — 寻找宿主机与邻居 VM"

# 7.1 网络拓扑分析
info "网络拓扑分析..."
MY_IP=""
GW_IP=""
GW_IFACE=""

while IFS= read -r line; do
    if [[ "$line" =~ ^default ]]; then
        GW_IP=$(echo "$line" | awk '{print $2}')
        GW_IFACE=$(echo "$line" | awk '{print $NF}')
    fi
done < <(ip route show 2>/dev/null || route -n 2>/dev/null || true)

if [[ -n "$GW_IFACE" ]]; then
    MY_IP=$(ip addr show "$GW_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
fi
[[ -z "$MY_IP" ]] && MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

label "本机 IP:" "${MY_IP:-未知}"
label "网关:"    "${GW_IP:-未知} (${GW_IFACE:-未知})"

# 7.2 ARP 扫描
if [[ -n "$MY_IP" ]] && [[ -n "$GW_IFACE" ]]; then
    echo ""
    info "ARP 扫描（发现局域网邻居）..."

    if check_cmd arp-scan; then
        ARP_OUT=$(arp-scan --local --interface="$GW_IFACE" --numeric --retry=2 2>/dev/null || true)
        if [[ -n "$ARP_OUT" ]]; then
            NEIGHBORS=$(echo "$ARP_OUT" | grep -v "^$MY_IP" | grep -v "^$GW_IP" | grep -P '^[\d.]+[\s]+[\w:]+' || true)
            N_COUNT=$(echo "$NEIGHBORS" | grep -c . 2>/dev/null || echo 0)
            if [[ "$N_COUNT" -gt 0 ]]; then
                warn "发现 ${N_COUNT} 个同网段主机（可能是邻居 VM）"
                echo "$NEIGHBORS" | while IFS= read -r line; do
                    nip=$(echo "$line" | awk '{print $1}')
                    nmac=$(echo "$line" | awk '{print $2}')
                    if echo "$nmac" | grep -qi "^52:54:00"; then
                        sub "  ${nip} [${nmac}] ← KVM 默认 MAC"
                        NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + 1))
                    else
                        sub "  ${nip} [${nmac}]"
                    fi
                done
            fi
        fi
    elif check_cmd nmap; then
        NETSEG=$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')
        NMAP_OUT=$(nmap -sn -n --exclude "$MY_IP" "$NETSEG" 2>/dev/null || true)
        NMAP_HOSTS=$(echo "$NMAP_OUT" | grep -oP 'Nmap scan report for \K[\d.]+' | grep -v "^$GW_IP$" || true)
        NMAP_COUNT=$(echo "$NMAP_HOSTS" | grep -c . 2>/dev/null || echo 0)
        if [[ "$NMAP_COUNT" -gt 0 ]]; then
            warn "nmap 发现 ${NMAP_COUNT} 个同网段主机"
            echo "$NMAP_HOSTS" | while IFS= read -r nip; do
                nmac=$(arp -n "$nip" 2>/dev/null | tail -1 | awk '{print $3}')
                if echo "$nmac" | grep -qi "52:54:00"; then
                    sub "  ${nip} [${nmac}] ← KVM VM"
                else
                    sub "  ${nip}"
                fi
            done
            NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + NMAP_COUNT))
        fi
    else
        # 简单 ping 扫
        NETBASE=$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3}')
        for i in 1 2 3; do ping -c 1 -W 1 "${NETBASE}.${i}" &>/dev/null & done
        for i in 254; do ping -c 1 -W 1 "${NETBASE}.${i}" &>/dev/null & done
        wait 2>/dev/null; sleep 1
        ARP_ENTRIES=$(arp -n 2>/dev/null | grep -v "incomplete\|Address" | grep -v "$MY_IP" | grep -v "$GW_IP" | awk '{print $1, $3}')
        A_COUNT=$(echo "$ARP_ENTRIES" | grep -c . 2>/dev/null || echo 0)
        [[ "$A_COUNT" -gt 0 ]] && warn "ARP 表发现 ${A_COUNT} 个潜在邻居" && NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + A_COUNT))
    fi
fi

# 7.3 virbr0 网段扫描
echo ""
info "检查 virbr0 (libvirt NAT 网段)..."
if ip link show virbr0 &>/dev/null; then
    VIRBR_IP=$(ip addr show virbr0 2>/dev/null | grep "inet " | awk '{print $2}')
    warn "virbr0 存在 — 宿主机使用 libvirt NAT 网络"
    label "virbr0:" "${VIRBR_IP:-192.168.122.1}"
    if check_cmd nmap; then
        VIRBR_NET="192.168.122.0/24"
        [[ -n "$VIRBR_IP" ]] && VIRBR_NET=$(echo "$VIRBR_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')
        VSCAN=$(nmap -sn -T4 "$VIRBR_NET" 2>/dev/null || true)
        VUP=$(echo "$VSCAN" | grep -c "Host is up" 2>/dev/null || echo 0)
        if [[ "$VUP" -gt 1 ]]; then
            BAD "virbr0 网段发现 $((VUP - 1)) 个其他主机！可能是其他 VM"
            NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + VUP - 1))
        fi
    fi
fi

# 7.4 libvirt 端口扫描
echo ""
info "扫描 libvirt TCP 管理端口..."
for port in 16509 16514; do
    if timeout 2 bash -c "echo >/dev/tcp/${GW_IP}/${port}" 2>/dev/null; then
        bad "宿主机 ${GW_IP}:${port} 端口开放！"
        case $port in
            16509) warn "TCP 16509 — libvirt 未加密远程访问（安全风险！）" ;;
            16514) warn "TCP 16514 — libvirt TLS 远程访问" ;;
        esac
        add_risk 5 "libvirt 端口 ${port} 开放"

        # 尝试连接获取 VM 列表
        if check_cmd virsh; then
            echo ""
            info "尝试通过 virsh 连接 ${GW_IP}:${port}..."
            VIRSH_OUT=$(virsh -c "qemu+tcp://${GW_IP}/system" list --all 2>/dev/null || true)
            if [[ -n "$VIRSH_OUT" ]] && ! echo "$VIRSH_OUT" | grep -qi "error\|failed\|refused\|认证"; then
                bad "成功连接到宿主机 libvirtd！"
                echo ""
                echo "$VIRSH_OUT"
                echo ""
                VM_TOTAL=$(echo "$VIRSH_OUT" | grep -cP '\s+[0-9-]+\s+' 2>/dev/null || echo 0)
                VM_RUN=$(echo "$VIRSH_OUT" | grep -c "running" 2>/dev/null || echo 0)
                bad "宿主机上: ${VM_TOTAL} 个 VM，${VM_RUN} 个正在运行"
                add_risk 10 "virsh: 宿主机 ${VM_TOTAL} 个 VM"
                NEIGHBOR_COUNT=$((NEIGHBOR_COUNT + VM_TOTAL))
            else
                info "virsh 连接被拒绝（需认证或 ACL）"
            fi
        fi

        # 尝试 HTTP REST API (libvirt 新版本)
        if check_cmd curl; then
            REST_RESULT=$(curl -s -m 5 "http://${GW_IP}:${port}/api" 2>/dev/null || true)
            if [[ -n "$REST_RESULT" ]]; then
                found "libvirt REST API 可访问！"
                sub "${REST_RESULT:0:200}"
                add_risk 5 "libvirt REST API 未受保护"
            fi
        fi
    fi
done

# 7.5 宿主机 hostname 探测 (通过网关反向 DNS)
echo ""
info "通过网关反向 DNS 尝试获取宿主机名..."
if [[ -n "$GW_IP" ]]; then
    if check_cmd nmblookup; then
        GW_HOST=$(nmblookup -A "$GW_IP" 2>/dev/null | grep "<00>" | grep -v GROUP | awk '{print $1}' | head -1 || echo "")
        [[ -n "$GW_HOST" ]] && label "宿主机 NetBIOS:" "${GW_HOST}"
    fi
    if check_cmd host; then
        GW_DNS=$(host "$GW_IP" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//' || echo "")
        [[ -n "$GW_DNS" ]] && label "宿主机 DNS:" "${GW_DNS}"
    fi
fi

# ============================================================
#  8. 其他宿主机暴露接口
# ============================================================
header "【第八步】其他宿主机暴露接口"

# 8.1 QEMU Guest Agent
info "QEMU Guest Agent..."
if check_cmd systemctl; then
    QGA_STAT=$(systemctl is-active qemu-guest-agent 2>/dev/null || echo "inactive")
    if [[ "$QGA_STAT" == "active" ]]; then
        found "QEMU Guest Agent 运行中"
        label "qemu-ga 状态:" "active (宿主机可通过此通道与 VM 通信)"
    fi
fi

# 8.2 串口 / QEMU Monitor (可能的暴露)
echo ""
info "串口 / QEMU Monitor 探测..."
for tty in /dev/ttyS0 /dev/ttyS1 /dev/ttyUSB0; do
    if [[ -c "$tty" ]]; then
        # 只做检测，不阻塞读取（串口读取会卡死）
        sub "${tty} 存在，设置参数:"
        stty -F "$tty" 115200 -echo -icanon 2>/dev/null && sub "  115200, -echo" || sub "  不可配置"
    fi
done 2>/dev/null || true

# QEMU Monitor 探测（通过 /proc/cmdline 判断是否绑定了串口）
MONITOR_INFO=$(cat /proc/cmdline 2>/dev/null | grep -oP 'console=ttyS\d+' | head -1)
if [[ -n "$MONITOR_INFO" ]]; then
    sub "控制台: ${MONITOR_INFO}"
fi

# 检查是否有 QEMU virtio 控制台设备
for vport in /dev/vport*; do
    if [[ -c "$vport" ]]; then
        sub "${vport##*/} 可用 (virtio 串口)"
    fi
done 2>/dev/null || true

# 8.3 9p/virtfs 共享文件系统
echo ""
info "9p/virtfs 共享文件系统..."
MOUNT_INFO=$(mount -t 9p 2>/dev/null | head -5)
if [[ -n "$MOUNT_INFO" ]]; then
    warn "存在 9p/virtfs 共享文件系统！宿主机文件可能通过此挂载点暴露"
    echo "$MOUNT_INFO" | while IFS= read -r line; do sub "  ${line}"; done
    add_risk 5 "9p 共享文件系统存在"
else
    info "未发现 9p 共享文件系统"
fi

# 8.4 VM 环境变量
echo ""
info "VM 环境变量检测..."
for var in QEMU_QMP QEMU_MONITOR QEMU_SERIAL VIRTIO_CONSOLE; do
    VAL=$(printenv "$var" 2>/dev/null)
    [[ -n "$VAL" ]] && label "环境变量 ${var}:" "${VAL:0:80}"
done

# 8.5 kernel 参数中 QEMU 传递的信息
echo ""
info "内核启动参数中的宿主机信息..."
CMDLINE=$(cat /proc/cmdline 2>/dev/null)
for token in qemu= ovmf= seabios= vga= kvm= hostname= net.ifnames= biosdevname=; do
    VAL=$(echo "$CMDLINE" | grep -oP "${token}\S+" || echo "")
    [[ -n "$VAL" ]] && label "cmdline ${token}:" "${VAL}"
done

# ============================================================
#  9. 内存超售
# ============================================================
header "【第九步】内存超售检测"

if [[ -f /proc/meminfo ]]; then
    MEM_TOTAL=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    MEM_AVAIL=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo)
    COMMIT_LIMIT=$(awk '/CommitLimit/ {printf "%.0f", $2/1024}' /proc/meminfo)
    COMMITTED_AS=$(awk '/Committed_AS/ {printf "%.0f", $2/1024}' /proc/meminfo)
    SWAP_TOTAL=$(awk '/SwapTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    SWAP_USED=$(awk '/SwapTotal/{s=$2}/SwapFree/{f=$2} END{printf "%.0f", (s-f)/1024}' /proc/meminfo)

    label "内存:"       "${MEM_TOTAL} MB"
    label "可用:"       "${MEM_AVAIL} MB"
    label "Swap:"       "${SWAP_TOTAL} MB (使用 ${SWAP_USED} MB)"

    if [[ "$COMMIT_LIMIT" -gt 0 ]] && [[ "$COMMITTED_AS" -gt 0 ]]; then
        echo ""
        info "核心: 承诺内存对比..."
        OC_RATIO=$(awk "BEGIN {printf \"%.2f\", $COMMITTED_AS / $COMMIT_LIMIT}" 2>/dev/null)
        label "CommitLimit:"   "${COMMIT_LIMIT} MB"
        label "Committed_AS:"  "${COMMITTED_AS} MB"
        label "承诺比率:"      "$(color_val "$OC_RATIO" 0.8 1.0)x"

        if (( $(echo "$COMMITTED_AS > $COMMIT_LIMIT" | bc -l 2>/dev/null) )); then
            bad "内存已超售！"
            add_risk 8 "内存超售: Committed_AS > CommitLimit"
        elif (( $(echo "$OC_RATIO > 0.8" | bc -l 2>/dev/null) )); then
            warn "接近超售边界"
            add_risk 3 "承诺比率 ${OC_RATIO}x"
        fi
    fi

    # Balloon
    echo ""
    info "virtio_balloon..."
    if lsmod 2>/dev/null | grep -qi "virtio_balloon"; then
        BAD "virtio_balloon 已加载"
        if dmesg 2>/dev/null | grep -i "balloon" | grep -qi "inflate\|deflate"; then
            bad "Balloon 活跃（有充放气记录）—— 内存被宿主机回收的铁证！"
            dmesg 2>/dev/null | grep -i "balloon" | tail -2 | while read -r line; do sub "  ${line}"; done
            add_risk 7 "Balloon 活跃"
        else
            add_risk 4 "Balloon 已加载"
        fi
    else
        good "未加载 Balloon"
    fi
fi
add_max 3

# ============================================================
#  10. 综合评分
# ============================================================
header "【综合结论】检测报告"

[[ "$MAX_SCORE" -eq 0 ]] && MAX_SCORE=100
SCORE_PCT=$(awk "BEGIN {printf \"%d\", ($RISK_SCORE * 100) / $MAX_SCORE}" 2>/dev/null)

echo ""
echo -e "  ${BOLD}━━ 超售风险评估 ━━${NC}"
label "风险总分:"     "${RISK_SCORE} / ${MAX_SCORE}"
label "风险指数:"     "${SCORE_PCT}%"

if [[ "$SCORE_PCT" -le 10 ]] && [[ "$RISK_SCORE" -le 3 ]]; then
    GRADE="${GREEN}A${NC}"; DESC="几乎无超售"
elif [[ "$SCORE_PCT" -le 20 ]]; then
    GRADE="${GREEN}A${NC}"; DESC="几乎无超售"
elif [[ "$SCORE_PCT" -le 35 ]]; then
    GRADE="${GREEN}B${NC}"; DESC="轻度超售"
elif [[ "$SCORE_PCT" -le 50 ]]; then
    GRADE="${YELLOW}C${NC}"; DESC="中度超售"
elif [[ "$SCORE_PCT" -le 70 ]]; then
    GRADE="${RED}D${NC}"; DESC="严重超售"
else
    GRADE="${RED}F${NC}"; DESC="极度超售"
fi
label "超售等级:"     "${GRADE}"
label "评估:"         "${DESC}"

echo ""
echo -e "  ${BOLD}━━ 邻居 VM ━━${NC}"
if [[ "$NEIGHBOR_COUNT" -gt 0 ]]; then
    bad "检测到约 ${NEIGHBOR_COUNT} 个邻居 VM"
else
    info "未明确检测到邻居 VM（可能空闲，或网络隔离）"
fi
echo ""

echo -e "  ${BOLD}━━ 关键风险 ━━${NC}"
if [[ ${#REPORT_LINES[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}无明显超售${NC}"
else
    IFS=$'\n'
    SORTED=($(sort -t'+' -k2 -rn <<< "${REPORT_LINES[*]}"))
    unset IFS
    for line in "${SORTED[@]}"; do
        w=$(echo "$line" | grep -oP '(?<=\+)\d+')
        d=$(echo "$line" | sed 's/^+[0-9]*://')
        [[ "$w" -ge 6 ]] && echo -e "  ${RED}[严重]${NC} ${d}" && continue
        [[ "$w" -ge 3 ]] && echo -e "  ${YELLOW}[中等]${NC} ${d}" && continue
        echo -e "  ${NC}[轻微]${NC} ${d}"
    done
fi

echo ""
echo -e "  ${BOLD}━━ 获取到的宿主机信息 ━━${NC}"
if $HOST_INFO_FOUND; then
    good "成功从宿主机获取到 ${HOST_INFO_FOUND} 类信息"
else
    info "未获取到宿主机暴露的特殊信息"
fi

echo ""
echo -e "${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║  检测结束                                  ║${NC}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}结论说明:${NC}"
echo -e "  ──────────────────────────────────────────────"
echo -e "  ${DIM}KVM 安全隔离阻止 VM 直接访问宿主机信息（这是虚拟化安全的基石）。${NC}"
echo -e "  ${DIM}本脚本能获取到的是 KVM 在设计上允许 VM 知道的信息：${NC}"
echo -e "  ${DIM}  • CPUID leaves (KVM 版本、特性)${NC}"
echo -e "  ${DIM}  • DMI/SMBIOS (BIOS/主板厂商)${NC}"
echo -e "  ${DIM}  • /dev/kvm (KVM 模块版本)${NC}"
echo -e "  ${DIM}  • Steal Time (调度竞争 — 推断邻居)${NC}"
echo -e "  ${DIM}  • L3 Cache (推算物理核心数)${NC}"
echo -e "  ${DIM}  • 网络拓扑 (ARP/NAT/libvirt 端口)${NC}"
echo -e ""
echo -e "  ${YELLOW}如果宿主机开放了 libvirt TCP 端口(16509)且未认证，${NC}"
echo -e "  ${YELLOW}脚本可直连获取精确 VM 列表。否则只能通过旁路推断。${NC}"
echo ""
