import time
import numpy as np
import random
import matplotlib.pyplot as plt
import matplotlib
from digital_signature import creating_key, signature, check
from Rabin_IDA import share_secret, reconstruct_secret

# 设置中文字体支持
matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'SimSun', 'Arial Unicode MS']
matplotlib.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

# 测试参数
TEST_ROUNDS = 10
N, K = 9, 6
MESSAGE = b"This is a test message for threshold signature performance."

SECURITY_LEVELS = {
    1: {
        'name': 'ML-DSA-44',
        'description': 'NIST Level 2 (128-bit security)'
    },
    2: {
        'name': 'ML-DSA-65',
        'description': 'NIST Level 3 (192-bit security)'
    },
    3: {
        'name': 'ML-DSA-87',
        'description': 'NIST Level 5 (256-bit security)'
    }
}

results = {
    'split': {},
    'recover': {},
    'total': {}
}

def test_threshold_performance():
    for level, level_info in SECURITY_LEVELS.items():
        print(f"\n测试 {level_info['name']} ({level_info['description']})...")
        split_times, recover_times, total_times = [], [], []
        for i in range(TEST_ROUNDS):
            # 1. 生成密钥
            sk, pk = creating_key(level)
            # 2. 分割
            t0 = time.time()
            M, shares = share_secret(sk, N, K)
            t1 = time.time()
            split_times.append(t1 - t0)
            # 3. 恢复
            idxs = random.sample(range(N), K)
            subset = [shares[j] for j in idxs]
            t2 = time.time()
            recovered_sk = reconstruct_secret(subset, M, idxs)
            t3 = time.time()
            recover_times.append(t3 - t2)
            # 4. 签名+验签
            t4 = time.time()
            sig = signature(level, MESSAGE, recovered_sk)
            assert check(level, sig, pk, MESSAGE)
            t5 = time.time()
            # 总耗时 = 分割+恢复+签名+验签
            total_times.append((t1-t0)+(t3-t2)+(t5-t4))
            print(f"  轮次 {i+1}/{TEST_ROUNDS}: 分割 {split_times[-1]:.4f}s, 恢复 {recover_times[-1]:.4f}s, 总耗时 {total_times[-1]:.4f}s")
        # 统计
        results['split'][level] = {
            'mean': np.mean(split_times),
            'std': np.std(split_times),
            'min': np.min(split_times),
            'max': np.max(split_times)
        }
        results['recover'][level] = {
            'mean': np.mean(recover_times),
            'std': np.std(recover_times),
            'min': np.min(recover_times),
            'max': np.max(recover_times)
        }
        results['total'][level] = {
            'mean': np.mean(total_times),
            'std': np.std(total_times),
            'min': np.min(total_times),
            'max': np.max(total_times)
        }

def print_detailed_results():
    print("\n详细性能测试结果:")
    print("-" * 80)
    for operation, op_name in zip(['split', 'recover', 'total'], ['私钥分割', '私钥恢复', '总耗时']):
        print(f"\n{op_name}:")
        print(f"{'安全等级':<15} {'平均时间(秒)':<15} {'标准差':<15} {'最小值(秒)':<15} {'最大值(秒)':<15}")
        print("-" * 80)
        for level, level_info in SECURITY_LEVELS.items():
            data = results[operation][level]
            print(f"{level_info['name']:<15} {data['mean']:<15.4f} {data['std']:<15.4f} {data['min']:<15.4f} {data['max']:<15.4f}")

def plot_results():
    operations = ['split', 'recover', 'total']
    operation_names = {'split': '私钥分割', 'recover': '私钥恢复', 'total': '总耗时'}
    fig, ax = plt.subplots(figsize=(12, 8))
    bar_width = 0.25
    index = np.arange(len(operations))
    for i, level in enumerate(SECURITY_LEVELS.keys()):
        means = [results[op][level]['mean'] for op in operations]
        std_devs = [results[op][level]['std'] for op in operations]
        position = index + (i - 1) * bar_width
        bars = ax.bar(position, means, bar_width,
                      label=f"{SECURITY_LEVELS[level]['name']}",
                      edgecolor='none')
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.001,
                    f'{height:.4f}s', ha='center', va='bottom', fontsize=10)
    ax.set_title('Crystals-Dilithium 阈值签名不同安全等级的性能', fontsize=18)
    ax.set_ylabel('平均执行时间 (秒)', fontsize=14)
    ax.set_xticks(index)
    ax.set_xticklabels([operation_names[op] for op in operations], fontsize=12)
    ax.tick_params(axis='y', labelsize=12)
    ax.legend(fontsize=12)
    plt.tight_layout()
    plt.savefig('threshold_performance.png', dpi=300)
    plt.show()

if __name__ == "__main__":
    print("开始 Crystals-Dilithium 阈值签名性能测试...\n")
    print(f"每个操作重复测试 {TEST_ROUNDS} 次")
    print(f"测试消息: {MESSAGE}")
    test_threshold_performance()
    print_detailed_results()
    plot_results()
    print("\n测试完成! 结果已保存为 'threshold_performance.png'") 