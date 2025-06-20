from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
import time
import matplotlib.pyplot as plt
import numpy as np
import matplotlib

# 设置中文字体支持
matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'SimSun', 'Arial Unicode MS']
matplotlib.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

# 测试参数
TEST_ROUNDS = 10  # 每个操作重复测试的次数
MESSAGE = b'This is a test message for Crystals-Dilithium signature performance testing.'

# 安全等级映射
SECURITY_LEVELS = {
    1: {
        'name': 'ML-DSA-44',
        'algorithm': ML_DSA_44,
        'description': 'NIST Level 2 (128-bit security)'
    },
    2: {
        'name': 'ML-DSA-65',
        'algorithm': ML_DSA_65,
        'description': 'NIST Level 3 (192-bit security)'
    },
    3: {
        'name': 'ML-DSA-87',
        'algorithm': ML_DSA_87,
        'description': 'NIST Level 5 (256-bit security)'
    }
}

# 结果存储
results = {
    'keygen': {},
    'sign': {},
    'verify': {}
}

# 测试函数
def test_performance():
    for level, level_info in SECURITY_LEVELS.items():
        print(f"\n测试 {level_info['name']} ({level_info['description']})...")
        algorithm = level_info['algorithm']
        
        # 测试密钥生成
        keygen_times = []
        for i in range(TEST_ROUNDS):
            start_time = time.time()
            pk, sk, _ = algorithm.keygen()
            end_time = time.time()
            keygen_times.append(end_time - start_time)
            print(f"  密钥生成 - 轮次 {i+1}/{TEST_ROUNDS}: {keygen_times[-1]:.4f} 秒")
        
        # 测试签名
        sign_times = []
        for i in range(TEST_ROUNDS):
            # 为每次测试生成新密钥
            pk, sk, _ = algorithm.keygen()
            start_time = time.time()
            signature = algorithm.sign(sk, MESSAGE)
            end_time = time.time()
            sign_times.append(end_time - start_time)
            print(f"  签名 - 轮次 {i+1}/{TEST_ROUNDS}: {sign_times[-1]:.4f} 秒")
        
        # 测试验证
        verify_times = []
        for i in range(TEST_ROUNDS):
            # 为每次测试生成新密钥和签名
            pk, sk, _ = algorithm.keygen()
            signature = algorithm.sign(sk, MESSAGE)
            start_time = time.time()
            result = algorithm.verify(pk, MESSAGE, signature)
            end_time = time.time()
            verify_times.append(end_time - start_time)
            print(f"  验证 - 轮次 {i+1}/{TEST_ROUNDS}: {verify_times[-1]:.4f} 秒")
            if not result:
                print("  警告: 验证失败!")
        
        # 存储结果
        results['keygen'][level] = {
            'mean': np.mean(keygen_times),
            'std': np.std(keygen_times),
            'min': np.min(keygen_times),
            'max': np.max(keygen_times)
        }
        
        results['sign'][level] = {
            'mean': np.mean(sign_times),
            'std': np.std(sign_times),
            'min': np.min(sign_times),
            'max': np.max(sign_times)
        }
        
        results['verify'][level] = {
            'mean': np.mean(verify_times),
            'std': np.std(verify_times),
            'min': np.min(verify_times),
            'max': np.max(verify_times)
        }

# 绘制结果柱状图
def plot_results():
    operations = ['keygen', 'sign', 'verify']
    operation_names = {'keygen': '密钥生成', 'sign': '签名', 'verify': '验证'}
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
    ax.set_title('Crystals-Dilithium 不同安全等级的性能', fontsize=18)
    ax.set_ylabel('平均执行时间 (秒)', fontsize=14)
    ax.set_xticks(index)
    ax.set_xticklabels([operation_names[op] for op in operations], fontsize=12)
    ax.tick_params(axis='y', labelsize=12)
    ax.legend(fontsize=12, loc='upper left')
    plt.tight_layout()
    plt.savefig('dilithium_performance.png', dpi=300)
    plt.show()

# 打印详细结果
def print_detailed_results():
    print("\n详细性能测试结果:")
    print("-" * 80)
    
    for operation in ['keygen', 'sign', 'verify']:
        print(f"\n{operation.upper()}:")
        print(f"{'安全等级':<15} {'平均时间(秒)':<15} {'标准差':<15} {'最小值(秒)':<15} {'最大值(秒)':<15}")
        print("-" * 80)
        
        for level, level_info in SECURITY_LEVELS.items():
            data = results[operation][level]
            print(f"{level_info['name']:<15} {data['mean']:<15.4f} {data['std']:<15.4f} {data['min']:<15.4f} {data['max']:<15.4f}")

# 主函数
if __name__ == "__main__":
    print("开始 Crystals-Dilithium 性能测试...\n")
    print(f"每个操作重复测试 {TEST_ROUNDS} 次")
    print(f"测试消息: {MESSAGE}")
    
    test_performance()
    print_detailed_results()
    plot_results()
    
    print("\n测试完成! 结果已保存为 'dilithium_performance.png'")