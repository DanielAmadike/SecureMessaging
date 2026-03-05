"""
Performance Graphs
Creates visual comparison charts from benchmark results.

Requirements:
  pip install matplotlib --break-system-packages

Input:  Results.csv (from benchmark result)
Output: PNG image
"""

import csv
import matplotlib.pyplot as plt
import os


def read_results(filename="Results.csv") :
    """Reads results from CSV file"""
    if not os.path.exists(filename) :
        print(f"ERROR: {filename} not found!")
        print(f"Please run final_benchmark_with_far.py first to create {filename}")
        return None

    aes_data = []
    chacha_data = []

    with open(filename, 'r') as f :
        reader = csv.DictReader(f)
        for row in reader :
            if row['Algorithm'] == 'AES-GCM' :
                aes_data.append(row)
            else :
                chacha_data.append(row)

    return aes_data, chacha_data


def create_encryption_time_chart(aes_data, chacha_data) :
    """Creates bar chart comparing encryption times"""
    test_cases = [row['Test Case'] for row in aes_data]
    aes_times = [float(row['Enc Time (ms)']) for row in aes_data]
    chacha_times = [float(row['Enc Time (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(10, 6))

    x = range(len(test_cases))
    width = 0.35

    ax.bar([i - width / 2 for i in x], aes_times, width, label='AES-GCM', color='#4472C4')
    ax.bar([i + width / 2 for i in x], chacha_times, width, label='ChaCha20-Poly1305', color='#ED7D31')

    ax.set_xlabel('Test Case', fontsize=12)
    ax.set_ylabel('Encryption Time (ms)', fontsize=12)
    ax.set_title('Encryption Speed Comparison: AES-GCM vs ChaCha20-Poly1305', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([tc.replace('Test ', 'T') for tc in test_cases], rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_encryption_time.png', dpi=300, bbox_inches='tight')
    print(" Created: graph_encryption_time.png")
    plt.close()


def create_throughput_chart(aes_data, chacha_data) :
    """Creates bar chart comparing throughput"""
    test_cases = [row['Test Case'] for row in aes_data]
    aes_throughput = [float(row['Throughput (MB/s)']) for row in aes_data]
    chacha_throughput = [float(row['Throughput (MB/s)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(10, 6))

    x = range(len(test_cases))
    width = 0.35

    ax.bar([i - width / 2 for i in x], aes_throughput, width, label='AES-GCM', color='#4472C4')
    ax.bar([i + width / 2 for i in x], chacha_throughput, width, label='ChaCha20-Poly1305', color='#ED7D31')

    ax.set_xlabel('Test Case', fontsize=12)
    ax.set_ylabel('Throughput (MB/s)', fontsize=12)
    ax.set_title('Throughput Comparison: AES-GCM vs ChaCha20-Poly1305', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([tc.replace('Test ', 'T') for tc in test_cases], rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_throughput.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_throughput.png")
    plt.close()


def create_safety_chart(aes_data, chacha_data) :
    """Creates chart showing safety test results"""
    algorithms = ['AES-GCM', 'ChaCha20-Poly1305']
    pass_counts = [
        sum(1 for row in aes_data if row['Safety'] == 'PASS'),
        sum(1 for row in chacha_data if row['Safety'] == 'PASS')
    ]
    total_tests = [len(aes_data), len(chacha_data)]

    fig, ax = plt.subplots(figsize=(8, 6))

    x = range(len(algorithms))

    ax.bar(x, pass_counts, color=['#70AD47', '#70AD47'], edgecolor='black', linewidth=1.5)

    # Add "out of total" labels
    for i, (passed, total) in enumerate(zip(pass_counts, total_tests)) :
        ax.text(i, passed + 0.1, f'{passed}/{total}', ha='center', fontsize=12, fontweight='bold')

    ax.set_ylabel('Tests Passed', fontsize=12)
    ax.set_title('Safety Test Results (Tamper Detection)', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms)
    ax.set_ylim(0, max(total_tests) + 1)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_safety.png', dpi=300, bbox_inches='tight')
    print("✓ Created: graph_safety.png")
    plt.close()


def create_comparison_summary(aes_data, chacha_data) :
    """Creates summary comparison chart"""
    # Calculate averages
    aes_avg_enc = sum(float(row['Enc Time (ms)']) for row in aes_data) / len(aes_data)
    chacha_avg_enc = sum(float(row['Enc Time (ms)']) for row in chacha_data) / len(chacha_data)

    aes_avg_dec = sum(float(row['Dec Time (ms)']) for row in aes_data) / len(aes_data)
    chacha_avg_dec = sum(float(row['Dec Time (ms)']) for row in chacha_data) / len(chacha_data)

    aes_avg_throughput = sum(float(row['Throughput (MB/s)']) for row in aes_data) / len(aes_data)
    chacha_avg_throughput = sum(float(row['Throughput (MB/s)']) for row in chacha_data) / len(chacha_data)

    # Create grouped bar chart
    fig, ax = plt.subplots(figsize=(10, 6))

    metrics = ['Avg Enc Time\n(ms)', 'Avg Dec Time\n(ms)', 'Avg Throughput\n(MB/s)']
    aes_values = [aes_avg_enc, aes_avg_dec, aes_avg_throughput]
    chacha_values = [chacha_avg_enc, chacha_avg_dec, chacha_avg_throughput]

    x = range(len(metrics))
    width = 0.35

    ax.bar([i - width / 2 for i in x], aes_values, width, label='AES-GCM', color='#4472C4')
    ax.bar([i + width / 2 for i in x], chacha_values, width, label='ChaCha20-Poly1305', color='#ED7D31')

    ax.set_ylabel('Value', fontsize=12)
    ax.set_title('Overall Performance Summary', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    # Add value labels on bars
    for i, (a, c) in enumerate(zip(aes_values, chacha_values)) :
        ax.text(i - width / 2, a, f'{a:.3f}', ha='center', va='bottom', fontsize=9)
        ax.text(i + width / 2, c, f'{c:.3f}', ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig('graph_summary.png', dpi=300, bbox_inches='tight')
    print("Created: graph_summary.png")
    plt.close()


def main() :
    print("=" * 50)
    print(" " * 15 + "PERFORMANCE GRAPHS GENERATOR")
    print("=" * 50)

    # Check if matplotlib is installed
    try :
        import matplotlib
        print("\n✓ matplotlib is installed")
    except ImportError :
        print("\n✗ ERROR: matplotlib is not installed!")
        print("\nPlease install it:")
        print("  pip install matplotlib --break-system-packages")
        return

    # Read data
    print("\nReading Results.csv...")
    data = read_results()

    if data is None :
        return

    aes_data, chacha_data = data
    print(f"✓ Found {len(aes_data)} AES tests and {len(chacha_data)} ChaCha20 tests")

    # Create graphs
    print("\nGenerating graphs...")
    print("-" * 60)

    create_encryption_time_chart(aes_data, chacha_data)
    create_throughput_chart(aes_data, chacha_data)
    create_safety_chart(aes_data, chacha_data)
    create_comparison_summary(aes_data, chacha_data)

    print("-" * 50)
    print("\n All graphs created successfully!")
    print("\nGenerated files:")
    print("  • graph_encryption_time.png - Encryption speed comparison")
    print("  • graph_throughput.png      - Throughput comparison")
    print("  • graph_safety.png          - Safety test results")
    print("  • graph_summary.png         - Overall summary")

    print("\nInstructions:")
    print("  1. Open these PNG files")
    print("  3. Add figure captions:")
    print("     Figure X: Encryption Speed Comparison")
    print("     Figure Y: Throughput Comparison")

    print("\n" + "=" * 50)


if __name__ == "__main__" :
    main()