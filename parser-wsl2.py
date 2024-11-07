import subprocess

def run_program(file_path):
    try:
        print(f"Running {file_path}...")
        result = subprocess.run(
            ['python3', file_path], check=True, text=True, capture_output=True
        )
        # Print both stdout and stderr to diagnose
        if result.stdout:
            print(f"Output from {file_path}:\n{result.stdout}")
        if result.stderr:
            print(f"Error output from {file_path}:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running {file_path}: {e.stderr}")
        print(f"Return code: {e.returncode}")
    except Exception as e:
        print(f"Unexpected error occurred: {e}")

def main():
    # File paths for the two programs
    insecure_crypto_detection = 'ast5.py'
    race_condition_detection = 'race-condition5.py'

    # Display the file names
    print(f"Preparing to run the following scripts:\n1. {insecure_crypto_detection}\n2. {race_condition_detection}\n")

    # Run the insecure cryptographic algorithm detection
    run_program(insecure_crypto_detection)

    # Run the race condition detection
    run_program(race_condition_detection)

if __name__ == "__main__":
    main()