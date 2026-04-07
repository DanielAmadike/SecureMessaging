"""
Cryptographic Properties Graphs - SIMPLE VERSION
Reads from crypto_results.csv

Requirements:
  pip install matplotlib --break-system-packages

Input:  crypto_results.csv (from crypto_result_CSV.py)
Output: 2 PNG graphs
"""

import csv
import matplotlib.pyplot as plt
import os


def read_crypto_results(filename="crypto_results.csv") :
    """Reads crypto results from CSV file"""
    if not os.path.exists(filename) :
        print(f"ERROR: {filename} not found!")
        print(f"Please run crypto_properties_CSV.py first to create {filename}")
        return None

    data = {}

    with open(filename, 'r') as f :
        reader = csv.DictReader(f)
        for row in reader :
            metric = row['Metric']
            data[metric] = {
                'AES' : float(row['AES-GCM']),
                'AES_StdDev' : float(row['AES_StdDev']),
                'ChaCha' : float(row['ChaCha20-Poly1305']),
                'ChaCha_StdDev' : float(row['ChaCha_StdDev'])
            }

    return data


def graph_avalanche(data) :
    """Avalanche Effect Bar Chart"""
    avalanche = data['Avalanche_%']

    algorithms = ['AES-GCM', 'ChaCha20-Poly1305']
    values = [avalanche['AES'], avalanche['ChaCha']]
    errors = [avalanche['AES_StdDev'], avalanche['ChaCha_StdDev']]

    plt.figure(figsize=(8, 6))
    plt.bar(algorithms, values, color=['#4472C4', '#ED7D31'],
            edgecolor='black', linewidth=1.5, yerr=errors, capsize=10)

    plt.axhline(y=50, color='green', linestyle='--', linewidth=2, label='Ideal (50%)')
    plt.axhspan(45, 55, alpha=0.2, color='green', label='Acceptable (45-55%)')

    plt.ylabel('Bits Changed (%)', fontsize=12, fontweight='bold')
    plt.title('Avalanche Effect: 1-Bit Input Change', fontsize=14, fontweight='bold')
    plt.ylim(0, 60)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_avalanche.png', dpi=300, bbox_inches='tight')
    print("Created: graph_avalanche.png")
    plt.close()


def graph_entropy(data) :
    """Entropy Bar Chart (10KB only - most meaningful)"""
    entropy_10kb = data['Entropy_10KB']

    algorithms = ['AES-GCM', 'ChaCha20-Poly1305']
    values = [entropy_10kb['AES'], entropy_10kb['ChaCha']]

    plt.figure(figsize=(8, 6))
    plt.bar(algorithms, values, color=['#4472C4', '#ED7D31'],
            edgecolor='black', linewidth=1.5)

    plt.axhline(y=8.0, color='green', linestyle='--', linewidth=2, label='Maximum (8.0)')
    plt.axhspan(7.9, 8.0, alpha=0.2, color='green', label='Acceptable (>7.9)')

    plt.ylabel('Shannon Entropy', fontsize=12, fontweight='bold')
    plt.title('Ciphertext Entropy (10KB Messages)', fontsize=14, fontweight='bold')
    plt.ylim(7.85, 8.05)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig('graph_entropy.png', dpi=300, bbox_inches='tight')
    print("Created: graph_entropy.png")
    plt.close()


if __name__ == "__main__" :
    print("\n" + "=" * 60)
    print("GENERATING CRYPTOGRAPHIC PROPERTY GRAPHS")
    print("=" * 60)
    print("\nReading from crypto_results.csv...")

    data = read_crypto_results()

    if data is None :
        print("\nFailed to read CSV file!")
        print("\nTo fix:")
        print("  1. Run: python crypto_properties_CSV.py")
        print("  2. Then run this script again")
    else :
        print(f"\nLoaded data:")
        print(f"  Avalanche: AES={data['Avalanche_%']['AES']:.2f}%, ChaCha={data['Avalanche_%']['ChaCha']:.2f}%")
        print(f"  Entropy:   AES={data['Entropy_10KB']['AES']:.4f}, ChaCha={data['Entropy_10KB']['ChaCha']:.4f}")
        print("\nGenerating graphs...\n")

        graph_avalanche(data)
        graph_entropy(data)

        print("\n" + "=" * 60)
        print("DONE! Created 2 graphs:")
        print("  - graph_avalanche.png")
        print("  - graph_entropy.png")
        print("=" * 60 + "\n")