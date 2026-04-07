"""
Requirements:
  pip install matplotlib --break-system-packages

Input:  Results.csv (from BenchMark_SecureMessaging.py)
Output: 10 PNG graphs (300 DPI)
"""
import csv
import matplotlib.pyplot as plt
import numpy as np
import os


def read_results(filename="Results.csv") :
    """Reads results from CSV file"""
    if not os.path.exists(filename) :
        print(f"ERROR: {filename} not found!")
        print(f"Please run BenchMark_SecureMessaging.py first to create {filename}")
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

    print(f" Loaded {len(aes_data)} AES-GCM results")
    print(f" Loaded {len(chacha_data)} ChaCha20-Poly1305 results")

    return aes_data, chacha_data


def extract_size_label(test_case) :
    """Extract clean size label from test case string.
        'Test 1 - 16 B' -> '16B'
        'Test 7 - 1 KB' -> '1KB'
        'Test 10 - 10 KB' -> '10KB'
    """
    # Split by ' - ' and take the size part
    parts = test_case.split(' - ')
    if len(parts) >= 2 :
        # Remove extra spaces from size label
        return parts[1].replace(' ', '')
    return test_case


#  GRAPH 1: ENCRYPTION TIME
def create_encryption_time_chart(aes_data, chacha_data) :
    """Bar chart comparing encryption times"""
    test_cases = [row['Test Case'] for row in aes_data]
    size_labels = [extract_size_label(tc) for tc in test_cases]
    aes_times = [float(row['Enc Mean (ms)']) for row in aes_data]
    chacha_times = [float(row['Enc Mean (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(size_labels))
    width = 0.35

    bars1 = ax.bar([i - width / 2 for i in x], aes_times, width,
                   label='AES-GCM', color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=0.7)
    bars2 = ax.bar([i + width / 2 for i in x], chacha_times, width,
                   label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8, edgecolor='black', linewidth=0.7)

    ax.set_xlabel('Message Size', fontweight='bold', fontsize=12)
    ax.set_ylabel('Encryption Time (milliseconds)', fontweight='bold', fontsize=12)
    ax.set_title('Encryption Time Comparison Across Message Sizes',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, rotation=45, ha='right', fontsize=10)
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Add subtitle note
    ax.text(0.5, -0.15, 'Lower values indicate faster encryption',
            transform=ax.transAxes, ha='center', fontsize=10,
            style='italic', color='gray')

    plt.tight_layout()
    plt.savefig('Encryption_Time.png', dpi=300, bbox_inches='tight')
    print(" Created: Encryption_Time.png")
    plt.close()


#  GRAPH 2: DECRYPTION TIME
def create_decryption_time_chart(aes_data, chacha_data) :
    """Bar chart comparing decryption times"""
    test_cases = [row['Test Case'] for row in aes_data]
    size_labels = [extract_size_label(tc) for tc in test_cases]
    aes_times = [float(row['Dec Mean (ms)']) for row in aes_data]
    chacha_times = [float(row['Dec Mean (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(size_labels))
    width = 0.35

    bars1 = ax.bar([i - width / 2 for i in x], aes_times, width,
                   label='AES-GCM', color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=0.7)
    bars2 = ax.bar([i + width / 2 for i in x], chacha_times, width,
                   label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8, edgecolor='black', linewidth=0.7)

    ax.set_xlabel('Message Size', fontweight='bold', fontsize=12)
    ax.set_ylabel('Decryption Time (milliseconds)', fontweight='bold', fontsize=12)
    ax.set_title('Decryption Time Comparison Across Message Sizes',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, rotation=45, ha='right', fontsize=10)
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Add subtitle note
    ax.text(0.5, -0.15, 'Lower values indicate faster decryption',
            transform=ax.transAxes, ha='center', fontsize=10,
            style='italic', color='gray')

    plt.tight_layout()
    plt.savefig('Decryption_Time.png', dpi=300, bbox_inches='tight')
    print(" Created: Decryption_Time.png")
    plt.close()


#  GRAPH 3: THROUGHPUT (SEPARATE ENC/DEC)
def create_throughput_chart(aes_data, chacha_data) :
    """Line chart comparing encryption and decryption throughput separately"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    size_labels = [extract_size_label(row['Test Case']) for row in aes_data]

    aes_enc_throughput = [float(row['Enc Throughput (MB/s)']) for row in aes_data]
    aes_dec_throughput = [float(row['Dec Throughput (MB/s)']) for row in aes_data]
    chacha_enc_throughput = [float(row['Enc Throughput (MB/s)']) for row in chacha_data]
    chacha_dec_throughput = [float(row['Dec Throughput (MB/s)']) for row in chacha_data]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Encryption Throughput
    ax1.plot(sizes, aes_enc_throughput, marker='o', linewidth=2.5,
             markersize=7, label='AES-GCM', color='#FF6B6B')
    ax1.plot(sizes, chacha_enc_throughput, marker='s', linewidth=2.5,
             markersize=7, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax1.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=12)
    ax1.set_ylabel('Throughput (MB/s)', fontweight='bold', fontsize=12)
    ax1.set_title('Encryption Throughput vs Message Size',
                  fontweight='bold', fontsize=14, pad=15)
    ax1.set_xscale('log')
    ax1.legend(fontsize=11, frameon=True, shadow=True)
    ax1.grid(True, alpha=0.3, linestyle='--', which='both')

    # Add log scale note
    ax1.text(0.02, 0.98, 'X-axis uses logarithmic scale',
             transform=ax1.transAxes, fontsize=9, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    # Decryption Throughput
    ax2.plot(sizes, aes_dec_throughput, marker='o', linewidth=2.5,
             markersize=7, label='AES-GCM', color='#FF6B6B')
    ax2.plot(sizes, chacha_dec_throughput, marker='s', linewidth=2.5,
             markersize=7, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax2.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=12)
    ax2.set_ylabel('Throughput (MB/s)', fontweight='bold', fontsize=12)
    ax2.set_title('Decryption Throughput vs Message Size',
                  fontweight='bold', fontsize=14, pad=15)
    ax2.set_xscale('log')
    ax2.legend(fontsize=11, frameon=True, shadow=True)
    ax2.grid(True, alpha=0.3, linestyle='--', which='both')

    # Add log scale note
    ax2.text(0.02, 0.98, 'X-axis uses logarithmic scale',
             transform=ax2.transAxes, fontsize=9, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

    plt.tight_layout()
    plt.savefig('Throughput_Comparison.png', dpi=300, bbox_inches='tight')
    print(" Created: Throughput_Comparison.png")
    plt.close()


#  GRAPH 4: SCALING (Log-scale)
def create_scaling_chart(aes_data, chacha_data) :
    """Log-scale chart showing scaling behavior"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_times = [float(row['Enc Mean (ms)']) for row in aes_data]
    chacha_times = [float(row['Enc Mean (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_times, marker='o', linewidth=2.5,
            markersize=7, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_times, marker='s', linewidth=2.5,
            markersize=7, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=12)
    ax.set_ylabel('Encryption Time (milliseconds)', fontweight='bold', fontsize=12)
    ax.set_title('Encryption Time Scaling Across Message Sizes',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(True, alpha=0.3, linestyle='--', which='both')

    # Add log-log scale note
    ax.text(0.02, 0.98, 'Both axes use logarithmic scale',
            transform=ax.transAxes, fontsize=9, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.6))

    plt.tight_layout()
    plt.savefig('Performance_Scaling.png', dpi=300, bbox_inches='tight')
    print(" Created: Performance_Scaling.png")
    plt.close()


#  GRAPH 5: THROUGHPUT ASYMMETRY (Enc vs Dec)
def create_throughput_asymmetry_chart(aes_data, chacha_data) :
    """Bar chart showing encryption vs decryption throughput ratio"""
    test_cases = [row['Test Case'] for row in aes_data]
    size_labels = [extract_size_label(tc) for tc in test_cases]

    # Calculate ratios (Dec/Enc)
    aes_ratios = []
    chacha_ratios = []

    for row in aes_data :
        enc = float(row['Enc Throughput (MB/s)'])
        dec = float(row['Dec Throughput (MB/s)'])
        ratio = (dec / enc) if enc > 0 else 1.0
        aes_ratios.append(ratio)

    for row in chacha_data :
        enc = float(row['Enc Throughput (MB/s)'])
        dec = float(row['Dec Throughput (MB/s)'])
        ratio = (dec / enc) if enc > 0 else 1.0
        chacha_ratios.append(ratio)

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(size_labels))
    width = 0.35

    ax.bar([i - width / 2 for i in x], aes_ratios, width,
           label='AES-GCM', color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=0.7)
    ax.bar([i + width / 2 for i in x], chacha_ratios, width,
           label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8, edgecolor='black', linewidth=0.7)

    # Add horizontal line at 1.0 (symmetric)
    ax.axhline(y=1.0, color='gray', linestyle='--', linewidth=1.5, alpha=0.7,
               label='Perfect symmetry (1.0)')

    ax.set_xlabel('Message Size', fontweight='bold', fontsize=12)
    ax.set_ylabel('Decryption/Encryption Throughput Ratio', fontweight='bold', fontsize=12)
    ax.set_title('Encryption and Decryption Throughput Ratio',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, rotation=45, ha='right', fontsize=10)
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Add subtitle note
    ax.text(0.5, -0.15, 'Values <1.0 indicate decryption is slower than encryption',
            transform=ax.transAxes, ha='center', fontsize=10,
            style='italic', color='gray')

    plt.tight_layout()
    plt.savefig('Throughput_Asymmetry.png', dpi=300, bbox_inches='tight')
    print(" Created: Throughput_Asymmetry.png")
    plt.close()


#  GRAPH 6: TOTAL CPU TIME (Energy Proxy)
def create_cpu_time_chart(aes_data, chacha_data) :
    """Line chart showing total CPU time (energy proxy)"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_cpu = [float(row['Total CPU Time (ms)']) for row in aes_data]
    chacha_cpu = [float(row['Total CPU Time (ms)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_cpu, marker='o', linewidth=2.5,
            markersize=7, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_cpu, marker='s', linewidth=2.5,
            markersize=7, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=12)
    ax.set_ylabel('Total CPU Time (milliseconds)', fontweight='bold', fontsize=12)
    ax.set_title('Energy Efficiency (CPU Time as Proxy)',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=11, frameon=True, shadow=True, loc='upper left')
    ax.grid(True, alpha=0.3, linestyle='--', which='both')

    # Add mobile range highlight
    ax.axvspan(1024, 10240, alpha=0.1, color='green',
               label='Typical messaging range (1KB–10KB)')
    ax.legend(fontsize=11, frameon=True, shadow=True, loc='upper left')

    # Add log-log scale note
    ax.text(0.02, 0.98, 'Both axes use logarithmic scale\nLower values indicate better efficiency',
            transform=ax.transAxes, fontsize=9, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.6))

    plt.tight_layout()
    plt.savefig('Energy_CPU_Time.png', dpi=300, bbox_inches='tight')
    print(" Created: Energy_CPU_Time.png")
    plt.close()


#  GRAPH 7: OPERATIONS PER SECOND
def create_ops_per_sec_chart(aes_data, chacha_data) :
    """Bar chart showing operations per second"""
    test_cases = [row['Test Case'] for row in aes_data]
    size_labels = [extract_size_label(tc) for tc in test_cases]
    aes_ops = [float(row['Ops/sec']) for row in aes_data]
    chacha_ops = [float(row['Ops/sec']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(size_labels))
    width = 0.35

    ax.bar([i - width / 2 for i in x], aes_ops, width,
           label='AES-GCM', color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=0.7)
    ax.bar([i + width / 2 for i in x], chacha_ops, width,
           label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8, edgecolor='black', linewidth=0.7)

    ax.set_xlabel('Message Size', fontweight='bold', fontsize=12)
    ax.set_ylabel('Operations per Second', fontweight='bold', fontsize=12)
    ax.set_title('Message Processing Rate (Operations per Second)',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, rotation=45, ha='right', fontsize=10)
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Add subtitle note
    ax.text(0.5, -0.15, 'Higher values indicate better message processing capability',
            transform=ax.transAxes, ha='center', fontsize=10,
            style='italic', color='gray')

    plt.tight_layout()
    plt.savefig('Energy_Ops_Per_Sec.png', dpi=300, bbox_inches='tight')
    print(" Created: Energy_Ops_Per_Sec.png")
    plt.close()


#  GRAPH 8: CPU TIME PER BYTE
def create_cpu_per_byte_chart(aes_data, chacha_data) :
    """Line chart showing CPU time per byte (normalized energy cost)"""
    sizes = [int(row['Message Size (B)']) for row in aes_data]
    aes_per_byte = [float(row['CPU Time/Byte (us)']) for row in aes_data]
    chacha_per_byte = [float(row['CPU Time/Byte (us)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(sizes, aes_per_byte, marker='o', linewidth=2.5,
            markersize=7, label='AES-GCM', color='#FF6B6B')
    ax.plot(sizes, chacha_per_byte, marker='s', linewidth=2.5,
            markersize=7, label='ChaCha20-Poly1305', color='#4ECDC4')

    ax.set_xlabel('Message Size (bytes)', fontweight='bold', fontsize=12)
    ax.set_ylabel('CPU Time per Byte (microseconds)', fontweight='bold', fontsize=12)
    ax.set_title('Normalized Energy Cost per Byte',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(True, alpha=0.3, linestyle='--', which='both')

    # Add vertical line at crossover point (~10KB)
    ax.axvline(x=10240, color='red', linestyle='--', linewidth=1.5,
               alpha=0.6, label='Crossover point (~10KB)')
    ax.legend(fontsize=11, frameon=True, shadow=True)

    # Add log-log scale note
    ax.text(0.02, 0.98, 'Both axes use logarithmic scale\nLower values indicate better efficiency',
            transform=ax.transAxes, fontsize=9, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='lightcyan', alpha=0.6))

    plt.tight_layout()
    plt.savefig('Energy_CPU_Per_Byte.png', dpi=300, bbox_inches='tight')
    print(" Created: Energy_CPU_Per_Byte.png")
    plt.close()


#  GRAPH 9: SAFETY (FAR)
def create_safety_chart(aes_data, chacha_data) :
    """Bar chart showing False Accept Rate (security)"""
    test_cases = [row['Test Case'] for row in aes_data]
    size_labels = [extract_size_label(tc) for tc in test_cases]
    aes_far = [float(row['FAR (%)']) for row in aes_data]
    chacha_far = [float(row['FAR (%)']) for row in chacha_data]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(size_labels))
    width = 0.35

    ax.bar([i - width / 2 for i in x], aes_far, width,
           label='AES-GCM', color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=0.7)
    ax.bar([i + width / 2 for i in x], chacha_far, width,
           label='ChaCha20-Poly1305', color='#4ECDC4', alpha=0.8, edgecolor='black', linewidth=0.7)

    ax.set_xlabel('Message Size', fontweight='bold', fontsize=12)
    ax.set_ylabel('False Accept Rate (%)', fontweight='bold', fontsize=12)
    ax.set_title('Security Validation: False Accept Rate',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, rotation=45, ha='right', fontsize=10)
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_ylim([0, 1])  # 0-1% range

    # Add subtitle note
    ax.text(0.5, -0.15, '0% indicates perfect security (all tampering detected)',
            transform=ax.transAxes, ha='center', fontsize=10,
            style='italic', color='gray')

    plt.tight_layout()
    plt.savefig('Security_FAR.png', dpi=300, bbox_inches='tight')
    print(" Created: Security_FAR.png")
    plt.close()


#  GRAPH 10: MOBILE SUMMARY
def create_summary_chart(aes_data, chacha_data) :
    """Mobile range throughput comparison - throughput only"""
    # Filter for mobile messaging range (1KB to 10KB)
    mobile_sizes = ['Test 7 - 1 KB', 'Test 8 - 2 KB', 'Test 9 - 5 KB', 'Test 10 - 10 KB']

    aes_mobile = [row for row in aes_data if row['Test Case'] in mobile_sizes]
    chacha_mobile = [row for row in chacha_data if row['Test Case'] in mobile_sizes]

    # Average ONLY throughput metrics
    metrics = {
        'Encryption\nThroughput' : (
            np.mean([float(r['Enc Throughput (MB/s)']) for r in aes_mobile]),
            np.mean([float(r['Enc Throughput (MB/s)']) for r in chacha_mobile])
        ),
        'Decryption\nThroughput' : (
            np.mean([float(r['Dec Throughput (MB/s)']) for r in aes_mobile]),
            np.mean([float(r['Dec Throughput (MB/s)']) for r in chacha_mobile])
        )
    }

    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(metrics))
    width = 0.35

    aes_vals = [v[0] for v in metrics.values()]
    chacha_vals = [v[1] for v in metrics.values()]

    bars1 = ax.bar(x - width / 2, aes_vals, width, label='AES-GCM',
                   color='#FF6B6B', alpha=0.8, edgecolor='black', linewidth=0.7)
    bars2 = ax.bar(x + width / 2, chacha_vals, width, label='ChaCha20-Poly1305',
                   color='#4ECDC4', alpha=0.8, edgecolor='black', linewidth=0.7)

    ax.set_ylabel('Throughput (MB/s)', fontweight='bold', fontsize=12)
    ax.set_title('Mobile Messaging Throughput (1KB–10KB)',
                 fontweight='bold', fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics.keys(), fontsize=11)
    ax.legend(fontsize=11, frameon=True, shadow=True)
    ax.grid(axis='y', alpha=0.3, linestyle='--')

    # Add value labels on bars
    for bars in [bars1, bars2] :
        for bar in bars :
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height,
                    f'{height:.1f}',
                    ha='center', va='bottom', fontsize=11, fontweight='bold')

    # Add subtitle note
    ax.text(0.5, -0.12, 'Average throughput for typical messaging workload',
            transform=ax.transAxes, ha='center', fontsize=10,
            style='italic', color='gray')

    plt.tight_layout()
    plt.savefig('Mobile_Summary.png', dpi=300, bbox_inches='tight')
    print(" Created: Mobile_Summary.png")
    plt.close()


# MAIN FUNCTION
def main() :
     # Read data
    result = read_results()
    if result is None :
        return

    aes_data, chacha_data = result

    print("\n" + "-" * 70)
    print("GENERATING GRAPHS...")
    print("-" * 70 + "\n")

    # Time comparison graphs (2)
    create_encryption_time_chart(aes_data, chacha_data)
    create_decryption_time_chart(aes_data, chacha_data)

    # Throughput and scaling graphs (3)
    create_throughput_chart(aes_data, chacha_data)
    create_scaling_chart(aes_data, chacha_data)
    create_throughput_asymmetry_chart(aes_data, chacha_data)

    # Energy efficiency graphs (3)
    create_cpu_time_chart(aes_data, chacha_data)
    create_ops_per_sec_chart(aes_data, chacha_data)
    create_cpu_per_byte_chart(aes_data, chacha_data)

    # Security and summary graphs (2)
    create_safety_chart(aes_data, chacha_data)
    create_summary_chart(aes_data, chacha_data)

    print("\n" + "=" * 70)
    print(" ALL GRAPHS CREATED SUCCESSFULLY!")
    print("=" * 70)
    print("\nGRAPHS CREATED:")
    print("\n  PERFORMANCE:")
    print("    1. Encryption_Time.png")
    print("    2. Decryption_Time.png")
    print("    3. Throughput_Comparison.png")
    print("    4. Performance_Scaling.png")
    print("    5. Throughput_Asymmetry.png")
    print("\n  ENERGY:")
    print("    6. Energy_CPU_Time.png")
    print("    7. Energy_Ops_Per_Sec.png")
    print("    8. Energy_CPU_Per_Byte.png")
    print("\n  SECURITY & SUMMARY:")
    print("    9. Security_FAR.png")
    print("   10. Mobile_Summary.png")






if __name__ == "__main__" :
    main()