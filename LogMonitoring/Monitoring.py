import os
import time

def watch_firewall_log(file_path):
    try:
        if not os.path.isfile(file_path):
            print(f"Error: The log file '{file_path}' does not exist.")
            return

        print(f"Watching firewall log file: {file_path}")

        # Get the initial size of the file
        initial_size = os.path.getsize(file_path)

        while True:
            # Get the current size of the file
            current_size = os.path.getsize(file_path)

            # Check if new entries have been added to the file
            if current_size > initial_size:
                print("Detected new log entries!")

                # Open the log file and read the new entries
                with open(file_path, 'r') as file:
                    file.seek(initial_size)  # Move to the last read position
                    new_data = file.read(current_size - initial_size)

                    # Display the new log entries
                    print("New Log Entries:")
                    print(new_data)

                # Update the initial size to the current size
                initial_size = current_size

            # Wait for a short interval before checking again
            time.sleep(5)

    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")

if __name__ == "__main__":
    log_file_path = r'location of the path in text format'
    watch_firewall_log(log_file_path)
