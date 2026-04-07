# check_aes_ni.py
import platform
import subprocess

print("=" * 60)
print("AES-NI HARDWARE ACCELERATION CHECK")
print("=" * 60)

system = platform.system()

if system == "Windows" :
    print("\nSystem: Windows")
    print("\nChecking CPU features...")
    try :
        # Run wmic command
        result = subprocess.run(
            ["wmic", "cpu", "get", "name"],
            capture_output=True,
            text=True
        )
        print(f"\nCPU: {result.stdout.strip()}")

        print("\nTo check AES-NI support on Windows:")
        print("1. Download CPU-Z from: https://www.cpuid.com/softwares/cpu-z.html")
        print("2. Run CPU-Z")
        print("3. Go to 'Instructions' tab")
        print("4. Look for 'AES' in the list")

    except Exception as e :
        print(f"Error: {e}")

elif system == "Linux" :
    print("\nSystem: Linux")
    print("\nChecking CPU features...")
    try :
        # Check /proc/cpuinfo for AES flag
        with open("/proc/cpuinfo", "r") as f :
            cpuinfo = f.read()

        if "aes" in cpuinfo.lower() :
            print("\n✓ AES-NI IS SUPPORTED!")
            print("  Your CPU has hardware AES acceleration")
        else :
            print("\n✗ AES-NI NOT FOUND")
            print("  Your CPU does not support hardware AES")

        # Show CPU model
        for line in cpuinfo.split('\n') :
            if 'model name' in line :
                print(f"\nCPU: {line.split(':')[1].strip()}")
                break

    except Exception as e :
        print(f"Error: {e}")

elif system == "Darwin" :  # macOS
    print("\nSystem: macOS")
    print("\nChecking CPU features...")
    try :
        # Use sysctl to check for AES
        result = subprocess.run(
            ["sysctl", "-a"],
            capture_output=True,
            text=True
        )

        if "aes" in result.stdout.lower() :
            print("\n✓ AES-NI IS SUPPORTED!")
            print("  Your CPU has hardware AES acceleration")
        else :
            print("\n✗ AES-NI NOT FOUND")

        # Show CPU model
        cpu_result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True,
            text=True
        )
        print(f"\nCPU: {cpu_result.stdout.strip()}")

    except Exception as e :
        print(f"Error: {e}")

else :
    print(f"\nUnknown system: {system}")

print("\n" + "=" * 60)