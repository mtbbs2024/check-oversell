# KVM 宿主机超售检测脚本

**从 KVM 虚拟机内部检测宿主机是否存在资源超售（Over-provisioning / Overselling）**

## 快速使用

```bash
curl -sS -O https://raw.githubusercontent.com/mtbbs2024/check-oversell/main/check_oversell.sh
sudo bash check_oversell.sh
```

或一行命令：

```bash
sudo bash -c "$(curl -sS https://raw.githubusercontent.com/mtbbs2024/check-oversell/main/check_oversell.sh)"
```

## 检测原理

| 检测维度 | 核心方法 | 权重 |
|---------|---------|------|
| **CPU Steal Time** | 4 种负载场景采样（空闲/单线程/全核/波动） | 最高 |
| **宿主机 CPU 识别** | 内置 60+ 种服务器 CPU 数据库，对比 vCPU 数量 | 高 |
| **L3 Cache 分析** | 通过 L3 缓存大小反推宿主物理核心数 | 高 |
| **CPU 扩展效率** | sysbench 单线程 vs 多线程性能比 | 高 |
| **virtio_balloon** | 检查气球驱动及其 dmesg 活动记录 | 高 |
| **Committed_AS** | 承诺内存 vs 承诺上限比值 | 高 |
| **IOPS 测试** | 4K 随机写入，IO 争抢最敏感指标 | 中 |
| **NUMA 拓扑** | vCPU 是否跨 NUMA 节点 | 中 |
| **中断分布** | vCPU pinning 检测 | 低 |

## 推荐安装的工具（可选，不装也能跑）

```bash
# Debian/Ubuntu
apt install sysbench cpuid

# CentOS/RHEL
yum install sysbench cpuid
```

## 输出解读

检测结果分 **A~F** 六个等级：

| 等级 | 含义 | 建议 |
|------|------|------|
| **A** | 几乎无超售 | 宿主机优秀 |
| **B** | 轻度超售 | 日常使用无影响 |
| **C** | 中度超售 | 高峰期可能性能下降 |
| **D** | 严重超售 | 建议联系服务商 |
| **F** | 极度超售 | 强烈建议更换 |

## 最佳实践

- **业务高峰期运行**——Steal Time 在高峰期最能反映问题
- **多次检测取平均**——单次检测有随机性
- **CPU Steal > 10% 是红线**——超过 10% 说明 CPU 争抢严重
- **同时检测 CPU + 内存 + IO 三个维度**——单项不说明问题

## License

MIT
