"""
UPDATED Performance Graphs Generator - WITH ENERGY METRICS
Creates visual comparison charts from benchmark results including energy efficiency.

Requirements:
  pip install matplotlib --break-system-packages

Input:  Results.csv (from BenchMark_SecureMessaging.py)
Output: PNG image files (8 graphs total)
"""

import csv
import matplotlib.pyplot as plt
import numpy as np
import os


def read_results(filename="Results.csv"):
    """Reads results from CSV file"""
    if not os.path.exists(filename):
        print(f"ERROR: {filename} not found!")
        print(f"Please run BenchMark_SecureMessaging.py first to create {filename}")
        return None

    aes_data = []
    chacha_data = []

    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Algorithm'] == 'AES-GCM':
                aes_data.append(row)
            else:
                chacha_data.append(row)

    print(f" Loaded {len(aes_data)} AES-GCM results")
    print(f" Loaded {len(chacha_data)} ChaCha20 results")

    return aes_data, chacha_data


# ========== GRAPH 1: ENCRYPTION TIME ==========
def create_encryption_time_chart(aes_data, chacha_data):
    """Bar chart comparing encryption times"""
    test_cases = [row['Test Case'] for row in aes_data]
    aes_times = [float(row['Enc Mean (ms)']) for row in aes_data]
    chacha_times = [float(row['Enc Mean (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(test_cases))
    width = 0.35

    bars1 = ax.bar([i - width/2 for i in x], aes_times, width,
                   label='AES-GCM', color='#FF6B6B', alpha=0.8)
    bars2 = ax.bar([i + width/2 for i in x], chacha_times, width,
                   label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8)

    ax.set_xlabel('Test Case', fontweight='bold', fontsize=11)
    ax.set_ylabel('Encryption Time (ms)', fontweight='bold', fontsize=11)
    ax.set_title('Encryption Time Comparison\n(Lower = Faster)',
                fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(test_cases, rotation=45, ha='right', fontsize=9)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_encryption_time.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_encryption_time.png")
    plt.close()


# ========== GRAPH 2: THROUGHPUT ==========
def create_throughput_chart(aes_data, chacha_data):
    """Line chart comparing throughput"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_throughput = [float(row['Throughput (MB/s)']) for row in aes_data]
    chacha_throughput = [float(row['Throughput (MB/s)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_throughput, marker='o', linewidth=2,
           markersize=6, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_throughput, marker='s', linewidth=2,
           markersize=6, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=11)
    ax.set_ylabel('Throughput (MB/s)', fontweight='bold', fontsize=11)
    ax.set_title('Throughput vs Message Size\n(Higher = Better)',
                fontweight='bold', fontsize=13)
    ax.set_xscale('log')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_throughput.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_throughput.png")
    plt.close()


# ========== GRAPH 3: SCALING (Log-scale) ==========
def create_scaling_chart(aes_data, chacha_data):
    """Log-scale chart showing scaling behavior"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_times = [float(row['Enc Mean (ms)']) for row in aes_data]
    chacha_times = [float(row['Enc Mean (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_times, marker='o', linewidth=2,
           markersize=6, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_times, marker='s', linewidth=2,
           markersize=6, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=11)
    ax.set_ylabel('Encryption Time (ms)', fontweight='bold', fontsize=11)
    ax.set_title('Scaling Behavior (Log-Log Scale)\n(Lower = Better)',
                fontweight='bold', fontsize=13)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3, which='both')

    plt.tight_layout()
    plt.savefig('graph_scaling.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_scaling.png")
    plt.close()


# ========== GRAPH 4: SAFETY (FAR) ==========
def create_safety_chart(aes_data, chacha_data):
    """Bar chart showing False Accept Rate (security)"""
    test_cases = [row['Test Case'] for row in aes_data]
    aes_far = [float(row['FAR (%)']) for row in aes_data]
    chacha_far = [float(row['FAR (%)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(test_cases))
    width = 0.35

    ax.bar([i - width/2 for i in x], aes_far, width,
          label='AES-GCM', color='#FF6B6B', alpha=0.8)
    ax.bar([i + width/2 for i in x], chacha_far, width,
          label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8)

    ax.set_xlabel('Test Case', fontweight='bold', fontsize=11)
    ax.set_ylabel('False Accept Rate (%)', fontweight='bold', fontsize=11)
    ax.set_title('Security: Tampering Detection (FAR)\n(Lower = Better, 0% = Perfect)',
                fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(test_cases, rotation=45, ha='right', fontsize=9)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    ax.set_ylim([0, 1])  # 0-1% range

    plt.tight_layout()
    plt.savefig('graph_safety.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_safety.png")
    plt.close()


# ========== GRAPH 5: Combined metrics ==========
def create_summary_chart(aes_data, chacha_data):
    """Multi-metric comparison for mobile range"""
    # Filter for mobile messaging range (1KB to 10KB)
    mobile_sizes = ['Test 7 - 1 KB', 'Test 8 - 2 KB', 'Test 9 - 5 KB', 'Test 10 - 10 KB']

    aes_mobile = [row for row in aes_data if row['Test Case'] in mobile_sizes]
    chacha_mobile = [row for row in chacha_data if row['Test Case'] in mobile_sizes]

    # Average metrics
    metrics = {
        'Enc Time\n(ms)': (
            np.mean([float(r['Enc Mean (ms)']) for r in aes_mobile]),
            np.mean([float(r['Enc Mean (ms)']) for r in chacha_mobile])
        ),
        'Throughput\n(MB/s)': (
            np.mean([float(r['Throughput (MB/s)']) for r in aes_mobile]),
            np.mean([float(r['Throughput (MB/s)']) for r in chacha_mobile])
        ),
        'FAR\n(%)': (
            np.mean([float(r['FAR (%)']) for r in aes_mobile]),
            np.mean([float(r['FAR (%)']) for r in chacha_mobile])
        )
    }

    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(metrics))
    width = 0.35

    aes_vals = [v[0] for v in metrics.values()]
    chacha_vals = [v[1] for v in metrics.values()]

    bars1 = ax.bar(x - width/2, aes_vals, width, label='AES-GCM',
                   color='#FF6B6B', alpha=0.8)
    bars2 = ax.bar(x + width/2, chacha_vals, width, label='ChaCha20-Poly1305',
                   color='#4ECDC4', alpha=0.8)

    ax.set_ylabel('Value', fontweight='bold', fontsize=11)
    ax.set_title('Mobile Messaging Performance Summary (1-10KB)\n(Normalized Metrics)',
                fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics.keys(), fontsize=10)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.2f}', ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig('graph_summary.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_summary.png")
    plt.close()


# ==========  GRAPH 6: TOTAL CPU TIME (Energy Proxy) ==========
def create_cpu_time_chart(aes_data, chacha_data):
    """Line chart showing total CPU time (energy proxy)"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_cpu = [float(row['Total CPU Time (ms)']) for row in aes_data]
    chacha_cpu = [float(row['Total CPU Time (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_cpu, marker='o', linewidth=2,
           markersize=6, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_cpu, marker='s', linewidth=2,
           markersize=6, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=11)
    ax.set_ylabel('Total CPU Time (ms)', fontweight='bold', fontsize=11)
    ax.set_title('Energy Efficiency: Total CPU Time\n(Lower = Better Battery Life)',
                fontweight='bold', fontsize=13)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3, which='both')

    # Add annotation for mobile range
    ax.axvspan(1024, 10240, alpha=0.1, color='green', label='Mobile Range (1-10KB)')

    plt.tight_layout()
    plt.savefig('graph_energy_cpu_time.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_energy_cpu_time.png")
    plt.close()


# ========== GRAPH 7: OPERATIONS PER SECOND ==========
def create_ops_per_sec_chart(aes_data, chacha_data):
    """Bar chart showing operations per second"""
    test_cases = [row['Test Case'] for row in aes_data]
    aes_ops = [float(row['Ops/sec']) for row in aes_data]
    chacha_ops = [float(row['Ops/sec']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(test_cases))
    width = 0.35

    ax.bar([i - width/2 for i in x], aes_ops, width,
          label='AES-GCM', color='#FF6B6B', alpha=0.8)
    ax.bar([i + width/2 for i in x], chacha_ops, width,
          label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8)

    ax.set_xlabel('Test Case', fontweight='bold', fontsize=11)
    ax.set_ylabel('Operations per Second', fontweight='bold', fontsize=11)
    ax.set_title('Energy Efficiency: Operations per Second\n(Higher = More Efficient)',
                fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(test_cases, rotation=45, ha='right', fontsize=9)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_energy_ops_per_sec.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_energy_ops_per_sec.png")
    plt.close()


# ========== GRAPH 8: CPU TIME PER BYTE ==========
def create_cpu_per_byte_chart(aes_data, chacha_data):
    """Line chart showing CPU time per byte (normalized energy cost)"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_per_byte = [float(row['CPU Time/Byte (us)']) for row in aes_data]
    chacha_per_byte = [float(row['CPU Time/Byte (us)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_per_byte, marker='o', linewidth=2,
           markersize=6, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_per_byte, marker='s', linewidth=2,
           markersize=6, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=11)
    ax.set_ylabel('CPU Time per Byte (μs)', fontweight='bold', fontsize=11)
    ax.set_title('Normalized Energy Cost\n(Lower = More Energy Efficient per Byte)',
                fontweight='bold', fontsize=13)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3, which='both')

    # Add vertical line at crossover point (~10KB)
    ax.axvline(x=10240, color='red', linestyle='--', linewidth=1,
              alpha=0.5, label='Crossover (~10KB)')

    plt.tight_layout()
    plt.savefig('graph_energy_cpu_per_byte.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_energy_cpu_per_byte.png")
    plt.close()


# ========== MAIN FUNCTION ==========
def main():
    """Generate all graphs"""
    print("\n" + "=" * 50)
    print("GRAPH GENERATOR - WITH ENERGY METRICS")
    print("=" * 50 + "\n")

    # Read data
    result = read_results()
    if result is None:
        return

    aes_data, chacha_data = result

    print("\n" + "-" * 70)
    print("GENERATING GRAPHS...")
    print("-" * 70 + "\n")

    # Original 5 graphs
    create_encryption_time_chart(aes_data, chacha_data)
    create_throughput_chart(aes_data, chacha_data)
    create_scaling_chart(aes_data, chacha_data)
    create_safety_chart(aes_data, chacha_data)
    create_summary_chart(aes_data, chacha_data)

    # NEW: 3 energy efficiency graphs
    create_cpu_time_chart(aes_data, chacha_data)
    create_ops_per_sec_chart(aes_data, chacha_data)
    create_cpu_per_byte_chart(aes_data, chacha_data)

    print("\n" + "=" * 50)
    print(" ALL 8 GRAPHS CREATED SUCCESSFULLY!")
    print("=" * 50)
    print("\nGRAPHS CREATED:")
    print("  1. graph_encryption_time.png    - Encryption time comparison")
    print("  2. graph_throughput.png          - Throughput vs message size")
    print("  3. graph_scaling.png             - Scaling behavior (log-log)")
    print("  4. graph_safety.png              - Security (FAR)")
    print("  5. graph_summary.png             - Mobile range summary")
    print("  6. graph_energy_cpu_time.png     - Total CPU time (energy proxy)")
    print("  7. graph_energy_ops_per_sec.png  - Operations per second")
    print("  8. graph_energy_cpu_per_byte.png - CPU time per byte")
    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()
