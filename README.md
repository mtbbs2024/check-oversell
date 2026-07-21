# KVM 宿主机超售检测脚本

**从 KVM 虚拟机内部检测宿主机是否存在资源超售（Over-provisioning / Overselling），并探测同宿主机的邻居 VM**

## 快速使用

```bash
curl -sS -O https://raw.githubusercontent.com/mtbbs2024/check-oversell/master/check_oversell.sh
sudo bash check_oversell.sh
```

或一行命令：

```bash
sudo bash -c "$(curl -sS https://raw.githubusercontent.com/mtbbs2024/check-oversell/master/check_oversell.sh)"
```

## 检测原理

### 宿主机信息探测（从虚拟机内部穿透）

| 技术手段 | 探测内容 |
|---------|---------|
| **CPUID KVM leaves** | 通过 `0x40000000-0x40000010` CPUID 叶子读取 KVM 版本、特性标志、PV 特性 |
| **DMI/SMBIOS** | 读取宿主机暴露的产品名、BIOS 版本、主板信息 |
| **L3 Cache 大小** | 反推宿主机物理核心数（Intel ~1.375MB/核，AMD EPYC 每CCD/32MB） |
| **overcommit_memory** | 检查内核内存超售策略 |
| **virtio_balloon dmesg** | 检查气球驱动是否有充放气活动记录 |

### 邻居 VM 探测（五大方法）

| 方法 | 工作原理 |
|------|---------|
| **Steal Time 模式分析** | 对 Steal Time 进行 8 次高频采样，分析波动/标准差/峰值模式，推断邻居 VM 活动 |
| **ARP 扫描** | 扫描同网段主机，检测 KVM 默认 MAC 前缀 `52:54:00` |
| **nmap 网段扫描** | 扫描网段活跃主机 + virbr0 NAT 网段 |
| **libvirt 端口探测** | 检测宿主机 16509/16514 端口是否开放，尝试直接连接获取 VM 列表 |
| **CPU 扩展效率** | sysbench 单线程 vs 多线程性能比，过低 = vCPU 在抢一个物理核心 |

### 超售检测维度

| 检测项 | 核心指标 | 权重 |
|-------|---------|------|
| **CPU Steal Time** | 4 种负载场景 + 时序波动分析 | 最高 |
| **L3 Cache 推算** | vCPU vs 物理核心对比 | 高 |
| **virtio_balloon** | 模块加载 + dmesg 充放气记录 | 高 |
| **Committed_AS** | 承诺内存 vs 上限比率 | 高 |
| **CPU 扩展效率** | 单线程/多线程性能比 | 高 |
| **内存承诺比率** | Committed_AS / CommitLimit | 高 |
| **IOPS 测试** | 4K 随机写入性能 | 中 |
| **NUMA 拓扑** | vCPU 跨节点分布 | 低 |

## 推荐安装的工具（可选）

```bash
# Debian/Ubuntu
apt install sysbench cpuid arp-scan nmap

# CentOS/RHEL
yum install sysbench cpuid arp-scan nmap
```

不装也能跑，装得越多检测越全面。

## 输出解读

### 超售等级 A~F

| 等级 | 风险指数 | 含义 | 建议 |
|------|---------|------|------|
| **A** | ≤10% | 几乎无超售 | 宿主机优秀 |
| **B** | ≤25% | 轻度超售 | 日常使用无影响 |
| **C** | ≤45% | 中度超售 | 高峰期可能性能下降 |
| **D** | ≤65% | 严重超售 | 建议联系服务商 |
| **F** | >65% | 极度超售 | 强烈建议更换 |

### 关键指标解读

- **CPU Steal > 10%** → 宿主机 CPU 超售，邻居在抢资源
- **vCPU/核心比 > 2** → CPU 超售（超线程极限是 2x）
- **Committed_AS > CommitLimit** → 内核承认内存超售
- **Balloon dmesg 有充放气记录** → 内存被宿主机回收的铁证
- **CPU 扩展效率 < 0.3** → vCPU 严重争抢物理核心
- **IOPS < 100** → 存储严重超售

## 局限性

1. **KVM 隔离设计阻止 VM 直接看到其他 VM** — 所有邻居检测都是旁路推断
2. 邻居 VM 空闲时无法被检测到（没有 CPU 争抢就没有 Steal）
3. 网络隔离的 VM 无法通过 ARP 发现
4. 结果仅供参考，建议多次检测取平均

## License

MIT
