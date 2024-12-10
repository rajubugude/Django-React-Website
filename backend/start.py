import os
import re
import csv
import pdb
import json
import time
import shutil
import paramiko
import subprocess
import pandas as pd
from scp import SCPClient
from datetime import datetime
import xml.etree.ElementTree as ET
from collections import defaultdict
from connection import SSHCommunicator
from concurrent.futures import ThreadPoolExecutor
from paramiko import SSHClient, AutoAddPolicy

datetime_pattern = re.compile(r"\d{8}_\d{6}")
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)



fc_56 = {
    'crash_type': set([' RTUL', 'NRT', 'CT', 'SIGFPE']),
    'signature': set([
        'UIB HDR-FTR MISMATCH',
        'ElProcessRxUntilSubFrameInd+0x48',
        'rachTaUpperThreshold_g',
        'processRachDLStrategyQueue+0x81c',
        'processRAReqAndNegRARspQueue+0x1a4',
        'ElProcessUlRandomAccess+0x44',
        '__aeabi_ldiv0',
    ])
}


# Form path to SEC_X folder and search for `core.` file
sec_folder_mapping = {
        'SEC_0':'sec0',
        'SEC_1':'sec1',
        'SEC_2':'sec2',
    }

def generate_csv(data, output_file):
    """
    Generate a CSV using pandas from the analysis data.
    :param data: List of dictionaries containing the analysis results.
    :param output_file: Path to the output CSV file.
    """
    # Create DataFrame
    df = pd.DataFrame(data)

    # Export to CSV
    df.to_csv(output_file, index=False)
    logger.info(f"CSV generated successfully at {output_file}")


def get_folders_in_directory(base_dir):
    try:
        # Get only directories from the base directory
        folders = [item for item in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, item))]
        return folders
    except Exception as e:
        print(f"Error occurred: {e}")
        return []


def process_alarm_logs_with_signature(base_dir):
    
    results = []  # List to store dictionaries for each folder's data

    # Iterate through each folder in the base directory
    for folder in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder)
        if not os.path.isdir(folder_path):
            continue  # Skip if not a directory

        alarm_log_path = os.path.join(folder_path, "AlarmHistoryLog_X.CSV")
        if not os.path.exists(alarm_log_path):
            print(f"No AlarmHistoryLog.CSV found in {folder_path}. Skipping.")
            continue

        print(f"Processing: {alarm_log_path}")
        
        # Initialize dictionary for the current folder
        folder_data = {"fc_id": None, "tar_file": None, "reason": None, "signature": []}

        # Read AlarmHistoryLog.CSV
        with open(alarm_log_path, "r") as csvfile:
            csv_reader = csv.reader(csvfile)
            lines = list(csv_reader)
            
            # Process the last 5 lines to extract FC and tar information
            for row in lines[-5:]:
                if "FC_" in row[-1] and ".tar" in row[-1]:
                    folder_data["fc_id"] = row[-1].split(" ")[0]  # Extract FC ID
                    folder_data["tar_file"] = row[-1].split(" ")[-1]  # Extract tar file name
                    folder_data["reason"] = row[-2] if len(row) > 9 else "Reason not found"
                    break
        
        # Find the sec0 folder corresponding to SEC_0 and extract signatures
        sec_folder = os.path.join(folder_path, "sec0")  # Assuming 'sec0' corresponds to SEC_0
        if os.path.exists(sec_folder):
            dbg_file_path = os.path.join(sec_folder, "L2_INIT_0.dbg")
            if os.path.exists(dbg_file_path):
                print(f"Reading signature from: {dbg_file_path}")
                with open(dbg_file_path, "r") as dbg_file:
                    for line in dbg_file:
                        if any(keyword in line.lower() for keyword in ["error", "crash", "failed"]):
                            folder_data["signature"].append(line.strip())

        results.append(folder_data)
    
    return results


def extract_management_server_ip(base_dir):
    """
    Extracts the 'managementserverip' from 'sidm.xml' files located in each folder within the base directory.

    Args:
        base_dir (str): The path to the directory containing folders with 'sidm.xml' files.

    Returns:
        dict: A dictionary mapping folder names to their respective 'managementserverip' values.
    """
    ip_mapping = {}

    try:
        # Iterate through all folders in the base directory
        for folder in os.listdir(base_dir):
            if "FC_56" in folder:
                folder_path = os.path.join(base_dir, folder)

                # Ensure it is a directory
                if not os.path.isdir(folder_path):
                    continue

                # Look for the sidm.xml file
                sidm_file = os.path.join(folder_path, "SIDM.xml")
                if not os.path.exists(sidm_file):
                    logger.debug(f"No sidm.xml found in {folder_path}. Skipping.")
                    continue

                try:
                    # Parse the sidm.xml file
                    tree = ET.parse(sidm_file)
                    root = tree.getroot()

                    # Find the managementserverip tag
                    ip_tag = root.find(".//ManagementServerInterfaceIP")
                    if ip_tag is not None:
                        ip_mapping[folder] = ip_tag.text

                    else:
                        logger.debug(f"managementserverip tag not found in {sidm_file}.")
                except ET.ParseError as e:
                    logger.debug(f"Error parsing {sidm_file}: {e}")

    except Exception as e:
        logger.debug(f"Error processing base directory {base_dir}: {e}")

    return ip_mapping



# def analyze_l2_init_file(local_dir, sec_name):
#     """
#     Analyze the L2_INIT_ files in the given sector directory for signatures and crash types.
    
#     :param local_dir: The local directory containing SEC_X folders.
#     :param sec_name: The sector (e.g., SEC_0) in which to look for L2_INIT_ files.
#     :return: A dictionary with matching signature and crash type, or None if not found.
#     """
#     try:
#         # Sector folder path
#         logger.info(f"Analyzing sector: {sec_name}")
#         sec_path = os.path.join(local_dir, sec_folder_mapping[sec_name])
#         if not os.path.isdir(sec_path):
#             logger.error(f"Sector directory not found: {sec_path}")
#             return None

#         # Search for L2_INIT_*.dbg files
#         l2_init_files = [
#             f for f in os.listdir(sec_path) if f.startswith("L2_INIT_") and f.endswith(".dbg")
#         ]
#         if not l2_init_files:
#             logger.info(f"No L2_INIT_ files found in sector: {sec_name}")
#             return None

#         for file_name in l2_init_files:
#             file_path = os.path.join(sec_path, file_name)
#             logger.info(f"Analyzing file: {file_path}")

#             # Read the file content
#             with open(file_path, "r") as file:
#                 file_content = file.read()

#             # Check for signatures
#             matching_signature = next((sig for sig in fc_56['signature'] if sig in file_content), None)
#             if matching_signature:
#                 logger.info(f"Signature found: {matching_signature}")
                
#                 # Check for crash types
#                 matching_crash_type = next((ctype for ctype in fc_56['crash_type'] if ctype in file_content), None)
#                 if matching_crash_type:
#                     logger.info(f"Crash type found: {matching_crash_type}")
#                     return {
#                         "signature": matching_signature,
#                         "crash_type": matching_crash_type,
#                     }
#                 else:

#                     logger.info(f"No crash type found for signature: {matching_signature}")
#             else:
#                 logger.info(f"No signature found in file: {file_name}")

#         # No matches found
#         logger.info("No matching signatures or crash types found in any file.")
#         return None

#     except Exception as e:
#         logger.exception("An error occurred while analyzing L2_INIT files.")
#         raise


def save_logs_to_file(log_dir, base_name, file, log_content):
    """
    Save the given log content to a file and return the file path.
    :param log_dir: Directory to save the log file.
    :param base_name: Base name for the log file.
    :param log_content: Content to save in the log file.
    :return: File path of the saved log.
    """
    # Create log directory if it doesn't exist
    # pdb.set_trace()
    file_log_path = os.path.join(log_dir,file)
    if not os.path.exists(file_log_path):
        os.makedirs(file_log_path)
    
    file_path = os.path.join(file_log_path, f"{base_name}.txt")
    with open(file_path, "w") as log_file:
        log_file.write(log_content)
    return file_path



def analyze_l2_init_file(local_dir, sec_name, output_dir, org_file, dictionary):
    """
    Analyze the L2_INIT_ files in the given sector directory for signatures and crash types.
    
    :param local_dir: The local directory containing SEC_X folders.
    :param sec_name: The sector (e.g., SEC_0) in which to look for L2_INIT_ files.
    :param output_dir: Directory to save extracted log files.
    :return: A dictionary with matching signature, crash type, log file link, and log content.
    """
    try:
        # Sector folder path
        logger.info(f"Analyzing sector: {sec_name}")
        sec_path = os.path.join(local_dir, sec_folder_mapping.get(sec_name, ""))
        if not os.path.isdir(sec_path):
            logger.error(f"Sector directory not found: {sec_path}")
            return None

        # Search for L2_INIT_*.dbg files
        l2_init_files = [
            f for f in os.listdir(sec_path) if f.startswith("L2_INIT_") and f.endswith(".dbg")
        ]
        if not l2_init_files:
            logger.info(f"No L2_INIT_ files found in sector: {sec_name}")
            return None
        # pdb.set_trace()

        for file_name in l2_init_files:
            file_path = os.path.join(sec_path, file_name)
            logger.info(f"Analyzing file: {file_path}")

            # Read the file content with error handling
            try:
                with open(file_path, "r") as file:
                    file_content = file.readlines()
            except Exception as e:
                logger.error(f"Error reading file {file_name}: {e}")
                continue  # Skip to the next file

            # Capture the last 30 lines of the file
            last_30_lines = "".join(file_content[-30:])
            last_30_lines_path = save_logs_to_file(output_dir, f"{file_name}_last30", org_file, last_30_lines)
            
            # Check for signatures and crash types
            full_content = "".join(file_content)
            matching_signature = next((sig for sig in fc_56['signature'] if sig in full_content), None)
            matching_crash_type = next((ctype for ctype in fc_56['crash_type'] if ctype in full_content), None)

            logger.info("Extracting the last 30 lines and signature and crash_type if found")
            dictionary[org_file] = {
                "signature": matching_signature or "N/A",
                "crash_type": matching_crash_type or  "N/A",
                "logs_link": last_30_lines_path,
                "gdb" : None
            }

        # No matches found in any file
        logger.info(f"No matching signatures or crash types found in sector: {sec_name}")
        return None

    except Exception as e:
        logger.exception("An error occurred while analyzing L2_INIT files.")
        return None

# This function should be used in the context of analyzing the L2_INIT files in a given directory structure.

def get_user_input():
    # Get date and time input from the user
    # start_date = input("Enter the start date (YYYY-MM-DD): ")
    # start_time = input("Enter the start time (HH:MM): ")
    # end_date = input("Enter the end date (YYYY-MM-DD): ")
    # end_time = input("Enter the end time (HH:MM): ")
    start_date = "2024-12-03"
    start_time = "01:00"
    end_date = "2024-12-03"
    end_time = "13:00"
    try:
        # Combine and parse input into datetime objects
        start_datetime = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
        end_datetime = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M")
        
        # Validate that the end time is after the start time
        if end_datetime <= start_datetime:
            print("Error: End datetime must be after start datetime.")
            return None

        print(f"Start: {start_datetime}, End: {end_datetime}")
        return start_datetime, end_datetime

    except ValueError as e:
        print(f"Invalid input format: {e}")
        return None


def copy_crash_tool(ssh_communicator, remote_path, local_path):
    """
    Copies the crash_untar_tool.sh from the remote directory to the local directory.
    """
    try:
        # Open SFTP connection
        sftp = ssh_communicator.client.open_sftp()
        # Define source and destination paths
        remote_file = f"{remote_path}/crash_untar_tool.sh"
        local_file = os.path.join(local_path, "crash_untar_tool.sh")
        # Copy the file
        sftp.get(remote_file, local_file)
        print(f"File 'crash_untar_tool.sh' copied to {local_path}")
        # Close SFTP
        sftp.close()
    except Exception as e:
        print(f"Error copying 'crash_untar_tool.sh': {e}")



def delete_enc_untar_in_directory(directory):
    try:
        # Iterate through all files in the directory
        for filename in os.listdir(directory):
            # Construct full file path
            file_path = os.path.join(directory, filename)
            # Check if the item is a file, then delete it
            # Check for .enc files or crash_untar_tool.sh and delete them
            # pdb.set_trace()
            if os.path.isfile(file_path or  filename.endswith(".enc") or filename == "crash_untar_tool.sh"):
                os.remove(file_path)
                print(f"Deleted: {file_path}")


    except Exception as e:
        print(f"Error occurred: {e}")



def run_crash_untar_tool(local_directory):
    """
    Executes the crash_untar_tool.sh script in the specified local directory.
    """
    try:
        # Change to the local directory
        print(f"Changing to directory: {local_directory}")
        os.chdir(local_directory)
        
        # Run the shell script
        print(f"Running './crash_untar_tool.sh'...")
        result = subprocess.run(["bash", "./crash_untar_tool.sh"], check=True, capture_output=True, text=True)

        # Print the output of the script
        print("Script Output:")
        print(result.stdout)
        print("Script Error (if any):")
        print(result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error executing script: {e}")
        print(f"Output: {e.output}")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")



def connector(host, username, password):
    try:
        object = SSHCommunicator(host, username, password)
        return object
    except Exception as e:
        print(f"Error connecting to device: {e}")
        return None



def get_correct_path(local_dir, filename):
    """Ensure path handling works across Windows and Unix systems."""
    if os.name == 'nt':  # For Windows
        return os.path.join(local_dir, filename).replace("\\", "/")



def process_file_line(file_lines, start_datetime, end_datetime, communicator, local_path):
    """Download all .enc files that match 'rac' or 'pv-rac' pattern and fall within the datetime range."""
    try:
        # Open a single SFTP connection
        sftp = communicator.client.open_sftp()
        print("SFTP connection established.")
        # pdb.set_trace()
        for line in file_lines:
            parts = line.split()
            filename = parts[-1][2:]  # Adjust to strip leading './'
            match = re.search(r"\d{8}_\d{6}", filename)
            if not match:
                print(f"Skipping {filename}: No valid datetime found.")
                continue

            try:
                # Check if the filename matches 'RAC' or 'PV-RAC' pattern
                if 'RAC' not in filename and 'PV-RAC' not in filename:
                    print(f"Skipping {filename}: Does not match 'RAC' or 'PV-RAC'.")
                    continue

                # Parse the timestamp from the filename and check if it falls within the date range
                file_datetime = datetime.strptime(match.group(), "%Y%m%d_%H%M%S")
                if start_datetime <= file_datetime <= end_datetime:
                    # pdb.set_trace()
                    print(f"Downloading {filename}...")
                    remote_file = f"/home/ems/Logs/{filename}"
                    local_file = get_correct_path(local_path, filename)
                    sftp.get(remote_file, local_file)
                    print(f"File downloaded: {local_file}")
                else:
                    print(f"Skipping {filename}: Does not fall within the specified date range.")

            except Exception as e:
                print(f"Error processing file {filename}: {e}")

    except Exception as e:
        print(f"Error in SFTP process: {e}")
    finally:
        # Close the SFTP connection once all files are processed
        sftp.close()
        print("SFTP connection closed.")



def run_crash_untar_tool(local_directory):
    """Runs the crash_untar_tool.sh script in the local directory."""
    try:
        os.chdir(local_directory)
        print(f"Changing to directory: {local_directory}")
        result = subprocess.run(["bash", "./crash_untar_tool.sh"], check=True, capture_output=True, text=True)

        print("Script Output:")
        print(result.stdout)
        print("Script Error (if any):")
        print(result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error executing script: {e}")
        print(f"Output: {e.output}")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")




def process_fc56_files(local_dir_path, node_ip_dictionary):
    """
    Process files in the specified directory for `FC_56` and organize `core.` files.
    
    Args:
        local_dir_path (str): Path to the directory containing extracted files.
        node_ip_dictionary (dict): Dictionary mapping filenames to host IPs.
    """
    logger = logging.getLogger("process_fc56_files")
    coredump_dir = os.path.join(local_dir_path, "CoreDump")

    # Ensure the CoreDump directory exists
    os.makedirs(coredump_dir, exist_ok=True)

    # Iterate through all files in the given directory
    for file_name in os.listdir(local_dir_path):
        if "FC_56" not in file_name:
            continue  # Skip files that don't contain FC_56

        match = re.search(r"SEC_\d", file_name)  # Extract SEC_X part
        if not match:
            logger.warning(f"Skipping {file_name}: No sector (SEC_X) found.")
            continue

        sec_folder_name = match.group()  # e.g., "SEC_0"
        host_ip = node_ip_dictionary.get(file_name)
        if not host_ip:
            logger.warning(f"Skipping {file_name}: Host IP not found.")
            continue

        # Construct paths for processing
        
        main_dir_path = os.path.join(local_dir_path, file_name)
        sec_folder_path = os.path.join(main_dir_path, sec_folder_mapping[sec_folder_name])
        if not os.path.isdir(sec_folder_path):
            logger.warning(f"Skipping {sec_folder_path}: Not a valid directory.")
            continue

        # Process inner files
        core_files_found = False
        for inner_file in os.listdir(sec_folder_path):
            if inner_file.startswith("core.lteLayer2"):
                core_files_found = True

                # Create destination folder structure
                host_dir = os.path.join(coredump_dir, f"{file_name}_{host_ip}", sec_folder_mapping[sec_folder_name])
                os.makedirs(host_dir, exist_ok=True)
                # pdb.set_trace()

                # Copy file to destination
                src_file = os.path.join(sec_folder_path, inner_file)
                dest_file = os.path.join(host_dir, inner_file)

                try:
                    shutil.copy(src_file, dest_file)
                    logger.info(f"Copied {src_file} to {dest_file}")
                except Exception as e:
                    logger.error(f"Failed to copy {src_file} to {dest_file}: {e}")

        if not core_files_found:
            logger.warning(f"No `core.` file found in {sec_folder_path}.")

# def process_fc56_files(local_dir_path, node_ip_dictionary):
#     """
#     Process files in the specified directory for `FC_56` and organize `core.` files.
    
#     Args:
#         local_dir_path (str): Path to the directory containing extracted files.
#         node_ip_dictionary (dict): Dictionary mapping filenames to host IPs.
#     """
#     pdb.set_trace()
#     coredump_dir = os.path.join(local_dir_path, "CoreDump")

#     # Ensure the CoreDump directory exists
#     if not os.path.exists(coredump_dir):
#         os.makedirs(coredump_dir)
    
#     # Iterate through all files in the given directory
#     for file_name in os.listdir(local_dir_path):
#         if "FC_56" in file_name:  # Filter for FC_56 files
#             match = re.search(r"SEC_\d", file_name)  # Extract SEC_X part
#             if match:
#                 sec_folder_name = match.group()  # e.g., "SEC_0"
#                 host_ip = node_ip_dictionary.get(file_name)
                
#                 if not host_ip:
#                     print(f"Skipping {file_name}: Host IP not found.")
#                     continue

#                 sec_folder = sec_folder_mapping[sec_folder_name]
#                 main_dir_path = os.path.join(local_dir_path, file_name)
#                 sec_folder_path = os.path.join(main_dir_path, sec_folder)
#                 if not os.path.isdir(sec_folder_path):
#                     print(f"Skipping {sec_folder_path}: Not a directory.")
#                     continue

#                 for inner_file in os.listdir(sec_folder_path):
#                     # pdb.set_trace()
#                     sanitized_file = inner_file.strip()  # Remove any leading/trailing whitespace
#                     if sanitized_file.startswith("core.lteLayer2"):
#                         host_dir = os.path.join(coredump_dir, file_name+'_'+host_ip, sec_folder)
#                         if not os.path.exists(host_dir):
#                             os.makedirs(host_dir)
                        
#                         src_file = os.path.join(sec_folder_path, inner_file)
#                         dest_file = os.path.join(host_dir, inner_file)


#                         shutil.copy(src_file, dest_file)
#                         print(f"Copied {src_file} to {dest_file}")

#                 else:
#                     print(f"No `core.` file found in {sec_folder_path}.")


def sudo_login(sudo_password, node_object):
    """
    Attempts to switch to sudo mode on the node.

    Args:
        sudo_password (str): The sudo password to use.
        node_object: The object representing the node connection.

    Returns:
        bool: True if sudo mode is successfully entered, False otherwise.
    """
    try:
        # Check if already in sudo mode
        output = node_object.execute('whoami')
        if 'root' in output:
            logger.info("Already in sudo mode.")
            return True

        logger.info("Attempting to switch to sudo mode.")

        # Clear buffer before sending `su` to avoid stale data interference
        node_object.execute('clear')

        # Send the su command
        node_object.send("su")
        logger.debug("Sent 'su' command. Waiting for password prompt.")

        # Wait for the password prompt (handle variations in prompt text)
        try:
            node_object.expect([":", "Password:", "password:"], timeout=15)
            logger.info("Password prompt detected. Sending sudo password.")
        except TimeoutError:
            logger.error("Password prompt not detected within timeout.")
            return False

        # Send the sudo password
        node_object.send(sudo_password)
        logger.info("Sudo password sent. Waiting for root prompt.")

        # Wait for the root prompt
        try:
            node_object.expect(["#"], timeout=15)
            logger.info("Switched to sudo mode successfully.")
            return True
        except TimeoutError:
            logger.error("Root prompt not detected after sending sudo password.")
            return False

    except Exception as e:
        logger.exception("An unexpected error occurred during sudo login.")
        return False


def copy_core_from_nms_to_node(nms_host, nms_username, nms_password, remote_path, node_object):
    try:
        logger.info("Initiating SCP from NMS to node...")
        
        # Form the SCP command
        scp_command = f"scp {nms_username}@{nms_host}:{remote_path}/core* ."
        node_object.send(scp_command)

        # Define possible prompts and their responses
        prompts = ["?", "password:", "Password:"]
        responses = {
            "?": "yes",
            "password:": nms_password,
            "Password:": nms_password,
        }
        logger.info("Waiting for SCP for 10 seconds...")
        # Handle prompts dynamically
        start_time = time.time()
        timeout = 10  # Total timeout for the SCP process
        buffer = ""
        while time.time() - start_time < timeout:
            if node_object.shell.recv_ready():
                chunk = node_object.shell.recv(1024).decode("utf-8")
                buffer += chunk
                logger.debug(f"Buffer updated: {chunk.strip()}")

                for prompt in prompts:
                    if prompt in buffer:
                        logger.info(f"Prompt '{prompt}' detected. Sending response.")
                        node_object.send(responses[prompt])
                        buffer = ""  # Reset buffer after handling a prompt
                        break

            time.sleep(0.1)

        # Verification step after SCP completes
        logger.info("Verifying copied files...")
        verify_command = "ls -ltr core*"
        output = node_object.execute(verify_command)
        if "No such file" in output or not output.strip():
            raise Exception("Verification failed: No core files found after SCP.")

        logger.info("Successfully copied core files from NMS to node.")
    except Exception as e:
        logger.error(f"Error during SCP operation: {e}")
        raise Exception(f"Error copying core files: {e}")


def untar_all_core_file(node_object):
    """
    Untar core files on the node, verify success, and remove .tar files if extraction is successful.
    
    Args:
        node_object: Instance of SSHCommunicator connected to the target node.
    """
    try:
        # List all .tgz files
        node_object.execute('clear')
        result = node_object.execute(f"ls | grep core.lte")
        tgz_files = [line.strip() for line in result.splitlines() if line.endswith('.tgz')]

        # Process each .tgz file
        for tgz_file in tgz_files:
            logger.info(f"Processing file: {tgz_file}")

            # Step 1: Decompress the .tgz file
            node_object.execute(f"gzip -d {tgz_file}", timeout=30)
            logger.info(f"Decompressed file: {tgz_file}")

            # Step 2: Extract the tar file
            tar_file = tgz_file[:-3] + 'tar'  # Replace .tgz with .tar
            node_object.execute(f"tar -xvf {tar_file}", timeout=20)
            logger.info(f"Extracted tar file: {tar_file}")

            # Step 3: Verify if the core file exists
            core_file = tgz_file[:-4]  # Remove .tgz to get core file name
            verify_result = node_object.execute(f"ls | grep -w {core_file}")
            if core_file in verify_result:
                logger.info(f"Extraction successful: {core_file}")
                # Step 4: Remove the .tar file
                node_object.execute(f"rm -f {tar_file}")
                logger.info(f"Removed tar file: {tar_file}")
                return core_file
            else:
                logger.warning(f"Extraction failed for {core_file}. Retaining {tar_file} for troubleshooting.")
    except Exception as e:
        logger.error(f"Error untarring files: {e}")
        raise


def login_sector(sector_password, file_name, node_object):
    """Login to a specific sector."""
    try:
        # Check if the file name contains `SEC_X`
        match = re.search(r"SEC_\d", file_name)  # Extract SEC_X part
        if not match:
            logger.info(f"Skipping {file_name}: No SEC_X found.")
            return False

        sec_name = match.group()  # e.g., "SEC_0"

        # Map SEC_X to folder names
        sec_folder_mapping = {
            'SEC_0': 'root@170.1.1.4',
            'SEC_1': 'root@170.1.1.5',
            'SEC_2': 'root@170.1.1.3',
        }

        # Ensure sec_name exists in the mapping
        if sec_name not in sec_folder_mapping:
            logger.error(f"Sector {sec_name} is not recognized. Check the sector-folder mapping.")
            return False

        ssh_command = f"ssh {sec_folder_mapping[sec_name]}"
        logger.debug(f"Executing command on node: {ssh_command}")
        node_object.send(ssh_command)

        # Step 1: Handle host authenticity and password prompts dynamically
        logger.debug("Waiting for prompts during SSH login.")
        prompts = ["?", "password:", "Password:"]
        responses = {
            "?": "yes\n",
            "password:": f"{sector_password}\n",
            "Password:": f"{sector_password}\n",
        }

        buffer = ""
        timeout = 30
        start_time = time.time()
        while time.time() - start_time < timeout:
            if node_object.shell.recv_ready():
                chunk = node_object.shell.recv(1024).decode("utf-8")
                buffer += chunk
                logger.debug(f"Buffer updated: {chunk.strip()}")

                for prompt in prompts:
                    if prompt in buffer:
                        response = responses.get(prompt, "")
                        if response:
                            logger.info(f"Prompt '{prompt}' detected. Sending response.")
                            node_object.send(response)
                            buffer = ""  # Reset buffer after handling a prompt
                            break
                        else:
                            logger.error(f"Unexpected prompt '{prompt}' received. Aborting login.")
                            return False

                # Exit the loop if login is successful (indicated by command prompt)
                if "#" in buffer or "root@TEJAS:~#" in buffer:
                    logger.info("Command prompt detected. Login successful.")
                    return True

            time.sleep(0.1)

        # If loop ends without detecting a prompt, raise timeout
        logger.error("Timeout occurred waiting for SSH login prompts.")
        return False

    except Exception as e:
        logger.exception("An error occurred during sector login.")
        return False


def get_core_files(node_object):
    """
    Retrieve and process the list of core files in the current directory.

    :param node_object: Node object for executing commands.
    :return: List of core file names.
    """
    try:
        # Clear terminal for a clean start (optional)
        node_object.execute('clear')
        
        # Execute the command to list core files
        output = node_object.execute('ls | grep core')

        # Process the output into a list
        core_files = [line.strip() for line in output.splitlines() if line.strip() and line[:4] == 'core']

        # Return the list of core files
        return core_files
    
    except Exception as e:
        logger.error(f"Failed to retrieve core files: {e}")
        raise


def execute_gdb_commands_and_getData(gdb_commands, node_object, gdb_run_command, core_files):
    """
    Execute GDB commands and retrieve the resulting output file.
    
    :param gdb_commands: List of commands to execute in GDB.
    :param node_object: Node object for executing commands remotely.
    :param gdb_run_command: Command to launch GDB with the binary and core file.
    :param core_files: List of core files to process.
    :return: Dictionary containing core file names and their GDB outputs.
    """
    gdb_outputs = {}  # Dictionary to store GDB output for each core file

    try:
        # Check if core files are provided
        if not core_files:
            logger.info("No core files provided. Skipping GDB execution.")
            return None
        
        for core_file in core_files:
            # Step 1: Launch GDB with the core file
            gdb_launch_cmd = f"{gdb_run_command}/{core_file}"
            logger.info(f"Launching GDB with: {gdb_launch_cmd}")
            
            # Execute the GDB launch command and wait for the "(gdb)" prompt
            gdb_prompt = "(gdb)"
            output = node_object.execute(gdb_launch_cmd, timeout=10)
            if gdb_prompt not in output:
                logger.error("GDB prompt not found after launch.")
                continue
            
            # Step 2: Execute GDB commands interactively
            logger.info("Executing GDB commands.")
            gdb_output = ""
            for command in gdb_commands:
                try:
                    # Send each GDB command and wait for the "(gdb)" prompt
                    command_output = node_object.execute(command, timeout=10)
                    gdb_output += f"\n[GDB Command: {command}]\n{command_output.strip()}"
                except TimeoutError:
                    logger.warning(f"Timeout occurred for GDB command: {command}")
                    gdb_output += f"\n[GDB Command: {command}]\n<TIMEOUT>"
            
            # Step 3: Store the collected output
            gdb_outputs[core_file] = gdb_output
        
        # Step 4: Exit GDB session

        logger.info("Exiting GDB session for current file node_object.")
        node_object.execute("quit", timeout=5)
        logger.info("GDB execution completed.")
        return gdb_outputs
    
    except Exception as e:
        logger.exception(f"Error while executing GDB commands: {e}")
        raise



def copy_to_nms(local_path, remote_host, remote_path, username, password):
    """
    Copies the CoreDump directory to the NMS server using SCP.

    Args:
        local_path (str): Path to the local CoreDump directory.
        remote_host (str): IP address or hostname of the remote NMS server.
        remote_path (str): Remote path where the directory should be copied.
        username (str): SSH username for the remote server.
        password (str): SSH password for the remote server.
    """
    try:
        # Validate local path
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local path does not exist: {local_path}")
        
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(remote_host, username=username, password=password)
        
        # Use SCP to copy the directory
        with SCPClient(ssh.get_transport()) as scp:
            print(f"Copying {local_path} to {remote_host}:{remote_path}...")
            scp.put(local_path, recursive=True, remote_path=remote_path)
            print(f"Successfully copied to {remote_host}:{remote_path}")
        
        # Close SSH connection
        ssh.close()
    except Exception as e:
        print(f"Error during SCP transfer: {e}")



def parse_gdb_output(gdb_dict):
    """
    Parse and organize the GDB dictionary output in a structured and readable format.
    
    :param gdb_dict: Dictionary containing GDB commands and their raw outputs.
    :return: A formatted string summarizing the GDB outputs.
    """
    parsed_output = {}

    for core_file, raw_output in gdb_dict.items():
        # Split the raw output by GDB command markers
        sections = raw_output.split("[GDB Command: ")
        
        structured_output = {}
        for section in sections:
            if not section.strip():
                continue
            
            # Extract the command and its output
            parts = section.split("]\n", 1)
            if len(parts) == 2:
                command = parts[0].strip()
                output = parts[1].strip()

                # Clean up and format output
                formatted_output = "\n".join(line.strip() for line in output.splitlines() if line.strip())
                structured_output[command] = formatted_output
            else:
                logger.warning(f"Malformed GDB section encountered in core file {core_file}. Skipping...")

        # Store structured output per core file
        parsed_output[core_file] = structured_output
    
    # Create a formatted summary
    formatted_summary = []
    for core, commands in parsed_output.items():
        formatted_summary.append(f"Core File: {core}")
        for cmd, output in commands.items():
            formatted_summary.append(f"\n  [Command]: {cmd}\n  [Output]:\n{output}")
        formatted_summary.append("\n" + "-" * 50)
    
    return "\n".join(formatted_summary)



def process_node_connections(node_ip_dictionary, username, password):
    """Establish SSH connections for all nodes, with fallback to a dummy node if unreachable."""
    # Load dummy node details from input.json
    dummy_node = None
    try:
        with open("input.json", "r") as file:
            input_data = json.load(file)
            dummy_node = input_data.get("dummy_node", {})
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading dummy node details from JSON: {e}")

    # Check if dummy node details are present
    if not dummy_node or not all(dummy_node.get(key) for key in ["ip", "username", "password"]):
        logger.error("Dummy node details are missing or incomplete in input.json.")
        dummy_node = None

    node_connections = {}
    ip_cache = {}  # Cache to store already-created objects for IPs
    # pdb.set_trace()
    for file, ip in node_ip_dictionary.items():
        connection_object = None
        try:
            # If the object for this IP already exists, reuse it
            if ip in ip_cache:
                connection_object = ip_cache[ip]
                if connection_object is not None:
                    node_connections[file] = [connection_object, ip]
                    logger.info(f"Reusing connection object for IP {ip} (File: {file}).")
                    continue

            # Attempt to connect to the node
            logger.info(f"Attempting to connect to node {ip} for file {file}.")
            connection_object = connector(ip, username, password)
            if connection_object == None:
                if dummy_node:
                    try:
                        logger.info(f"Attempting to connect to dummy node for file {file}.")
                        connection_object = connector(
                            dummy_node["ip"],
                            dummy_node["username"],
                            dummy_node["password"]
                        )
                        ip_cache[ip] = connection_object  # Cache only successful connections
                        node_connections[file] = [connection_object, ip] #here even it is connected with dummy node ip, but storing , main node ip instead
                        logger.info(f"Connected to dummy node {dummy_node['ip']} for file {file}.")
                    except Exception as dummy_e:
                        logger.error(f"Error connecting to dummy node: {dummy_e}")
                        node_connections[file] = [None, ip]  # Mark as failed for this file
                else:
                    logger.error(f"No dummy node available for file {file}. Marking as failed.")
                    node_connections[file] = [None, ip]  # Mark as failed for this file
            else:
                ip_cache[ip] = connection_object  # Cache only successful connections
                node_connections[file] = [connection_object, ip]
                logger.info(f"Connected to node {ip} for file {file}.")
        except Exception as e:
            logger.error(f"Error connecting to node {ip}: {e}")

    return node_connections


def extract_remote_path_from_nms_to_core(file_name, node_ip, logs_path):
    """
    Extract the remote path for `core.` files based on the file name structure.

    Args:
        file_name (str): Name of the file (e.g., `RAC-104_..._SEC_0_FC_56_...`).

    Returns:
        str: The constructed remote path to the `core.` file.
    """
    try:
        # Check if the file name contains `SEC_X`
        match = re.search(r"SEC_\d", file_name)  # Extract SEC_X part
        if not match:
            print(f"Skipping {file_name}: No SEC_X found.")
            return None
        
        sec_folder_name = match.group()  # e.g., "SEC_0"

        # Map SEC_X to folder names
        sec_folder_mapping = {
            'SEC_0': 'sec0',
            'SEC_1': 'sec1',
            'SEC_2': 'sec2',
        }
        sec_folder = sec_folder_mapping.get(sec_folder_name, sec_folder_name.lower())  # Default to lowercase SEC_X
        # Construct the remote path
        remote_path = f"{logs_path}/CoreDump/{file_name}_{node_ip}/{sec_folder}"
        print(f"Constructed remote path: {remote_path}")
        return remote_path

    except Exception as e:
        print(f"Error extracting remote path from {file_name}: {e}")
        return None


def clear_core_files_in_node(node_object, core_files):
    node_object.execute("clear")
    logger.info("Clearing core files")
    for core_file in core_files:
        logger.info(f"Clearing core file: {core_file}")
        node_object.execute(f" rm -rf {core_file}")
    logger.info("All the core files are cleared")

def write_final_dictionary_to_csv(final_dictionary, local_dir_path):
    """
    Writes the results stored in the final dictionary to a CSV file with clickable hyperlinks.

    Args:
        final_dictionary (dict): The dictionary containing processed results.
        local_dir_path (str): Path to the directory where the CSV should be saved.
    """
    os.makedirs(local_dir_path, exist_ok=True)
    output_csv_path = os.path.join(local_dir_path, "final_results.csv")

    try:
        with open(output_csv_path, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write the header
            csv_writer.writerow(["File", "Signature", "Crash Type", "Logs Link", "GDB Link"])
            
            # Write the rows
            for file, details in final_dictionary.items():
                logs_link = details.get("logs_link", "")
                gdb = details.get("gdb_link", "")

                # Format links using Excel HYPERLINK function if paths are present
                logs_hyperlink = f'=HYPERLINK("{logs_link}", "Logs")' if logs_link else ""
                gdb_hyperlink = f'=HYPERLINK("{gdb}", "GDB")' if gdb else ""

                csv_writer.writerow([
                    file,
                    details.get("signature", "N/A"),
                    details.get("crash_type", "N/A"),
                    logs_hyperlink,
                    gdb_hyperlink,
                ])

        logging.info(f"Results written to {output_csv_path}")
    except Exception as e:
        logging.error(f"Failed to write CSV: {e}")

def write_final_dictionary_to_csv(final_dictionary, local_dir_path):
    """
    Writes the results stored in the final dictionary to a CSV file.

    Args:
        final_dictionary (dict): The dictionary containing processed results.
        local_dir_path (str): Path to the directory where the CSV should be saved.
    """
    # Ensure the directory exists
    os.makedirs(local_dir_path, exist_ok=True)

    # Define a proper CSV file path
    output_csv_path = os.path.join(local_dir_path, "final_results.csv")

    try:
        # Write dictionary data to the CSV
        with open(output_csv_path, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write the header
            csv_writer.writerow(["File", "Signature", "Crash Type", "Logs Link", "GDB Link"])
            
            # Write the rows
            for file, details in final_dictionary.items():
                csv_writer.writerow([
                    file,
                    details.get("signature", ""),
                    details.get("crash_type", ""),
                    details.get("logs_link", ""),
                    details.get("gdb", ""),
                ])

        logging.info(f"Results written to {output_csv_path}")
    except Exception as e:
        logging.error(f"Failed to write CSV: {e}")


def parse_gdb_to_link(final_dictionary, parsed_gdb_output, output_dir, file_name):
    """
    Save the parsed GDB output to a file and update the final dictionary with the file path link.
    
    :param final_dictionary: The dictionary to update.
    :param parsed_gdb_output: The parsed GDB output to save.
    :param output_dir: The directory where the GDB dump will be stored.
    :param file_name: The name of the file being processed (used for naming the GDB dump file).
    """
    try:
        # Ensure the output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")

        # Define the GDB dump file path
        gdb_file_path = os.path.join(output_dir, f"{file_name}_gdb.txt")
        logger.debug(f"GDB file path: {gdb_file_path}")
        
        logger.info(f"Saving GDB output link to dictionary for file: {file_name}")
        # Save the parsed GDB output to the file
        with open(gdb_file_path, "w") as gdb_file:
            gdb_file.write(parsed_gdb_output)
        logger.info(f"GDB output saved to {gdb_file_path}")

        # Update the final dictionary with the file path link
        final_dictionary[file_name]['gdb'] = gdb_file_path
        logger.debug(f"Current dictionary state: {final_dictionary}")

    except Exception as e:
        logger.error(f"Failed to save GDB output for {file_name}: {e}")
        final_dictionary[file_name]['gdb'] = f"Failed to save GDB output for {file_name}"



def load_json_input(file_path):
    """Load input parameters from a JSON file."""
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.info(f"Error: JSON file '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        logger.info(f"Error parsing JSON file: {e}")
        return None


def main():
    # Step 1: Load Input Parameters from JSON
    json_file_path = "input.json"
    input_data = load_json_input(json_file_path)
    if not input_data:
        logger.error("Invalid input. Exiting.")
        return

    try:
        # Parse input parameters
        start_date = input_data.get("start_date")
        start_time = input_data.get("start_time")
        end_date = input_data.get("end_date")
        end_time = input_data.get("end_time")
        nms_host = input_data.get("nms_host")
        nms_username = input_data.get("nms_username")
        nms_password = input_data.get("nms_password")

        if not all([start_date, start_time, end_date, end_time, nms_host, nms_username, nms_password]):
            logger.error("Error: Missing required input parameters in JSON file.")
            return

        # Convert start and end date-time to datetime objects
        start_datetime = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
        end_datetime = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M")

        # Step 2: Create Local Directory
        local_dir_path = f"enc_untar_tool_{start_datetime.strftime('%Y%m%d_%H%M')}_to_{end_datetime.strftime('%Y%m%d_%H%M')}"
        parent_dir = "D:\\CoreAnalysis\\CoreAnalysis"
        local_dir_path = os.path.join(parent_dir, local_dir_path)
        os.makedirs(local_dir_path, exist_ok=True)
        print(f"Directory created: {local_dir_path}")
        # pdb.set_trace()
        nms_object_communicator = connector(nms_host, nms_username, nms_password)
        logs_path = "/home/ems/Logs"
        nms_object_communicator.execute(f"cd {logs_path}")
        start_str = start_datetime.strftime("%Y-%m-%d %H:%M")
        end_str = end_datetime.strftime("%Y-%m-%d %H:%M")

        files_list = nms_object_communicator.execute(f'find . -maxdepth 1 -type f -newermt "{start_str}" ! -newermt "{end_str}" -name "*.enc" ')
        process_file_line(files_list.splitlines()[1:], start_datetime, end_datetime, nms_object_communicator, local_dir_path)

        # Step 4: Copy and Run Crash Untar Tool
        remote_crash_dir = "/home/ems/Logs/SYS/crash"
        copy_crash_tool(nms_object_communicator, remote_crash_dir, local_dir_path)
        # pdb.set_trace()
        run_crash_untar_tool(local_dir_path)
        delete_enc_untar_in_directory(local_dir_path)
        node_ip_dictionary = extract_management_server_ip(local_dir_path) # extracting node ip of , only fc_56 files

        # Step 5:  process fc_56 in to local directory
        process_fc56_files(local_dir_path, node_ip_dictionary)
        # # collect all the fc's in the given input directory
        

        # # pdb.set_trace()
        # Step 6: copy coredump local directory to nms server
        local_coredump_path = os.path.join(local_dir_path, 'CoreDump')
        # # Copy CoreDump to NMS
        copy_to_nms(local_coredump_path, nms_host, logs_path, nms_username, nms_password)
        # Step 7: create file:node_ip dictionary 

        logger.info(f"Extracted Node IP Dictionary: {node_ip_dictionary}")
        final_dictionary = {}

        # Step 8: process each node file and get the gdb commands
        node_username = 'guest'
        node_password = 'iltwat'
        sudo_password = 'swtn100tj'
        node_copy_path = "/tmp/NFS_RAC/soc_rootfs/etc/tejas"
        gdb_run_path = '/tmp/tejas'
        gdb_run_command = 'gdb lteLayer2_fdd /etc/tejas'
        gdb_execute_commands = ["bt", 'thread 1', 'bt', 'thread 2', 'bt', 'thread 3', 'bt', 'q']
        #Get node connections
        # Step 9: get the connect objects 
        # pdb.set_trace()
        node_connector_objects = process_node_connections(node_ip_dictionary, node_username, node_password)
        flag = True
        local_logsdump_path = os.path.join(local_dir_path, 'LogsDump')
        for file in node_connector_objects.keys():
            sec_name_match = re.search(r"(SEC_\d)", file)
            if sec_name_match:
                sec_name = sec_name_match.group(1)  # Extract sector name (e.g., SEC_1)
                local_file_path = os.path.join(local_dir_path, file)
                analyze_l2_init_file(local_file_path, sec_name, local_logsdump_path, file, final_dictionary)
            if flag:
                try:
                    # Step 1: Initial logging and sudo login
                    logger.info('Currently working on file: %s', file)
                    node = node_connector_objects[file]
                    node_object = node[0]

                    if node_object is None:
                        logger.error(f"Node {node[1]} is not reachable.")
                        final_dictionary[file]['gdb']  = f"Node {node[1]} is not reachable"
                        continue

                    # Attempt sudo login
                    if not sudo_login(sudo_password, node_object):
                        logger.error(f"Failed to switch to sudo mode for node {node[1]}. Skipping.")
                        final_dictionary[file]['gdb']  = f"Failed to switch to sudo mode for node {node[1]}"
                        continue

                    # Step 2: Change to the working directory
                    try:
                        # Step 2: Change to the working directory
                        node_object.execute(f"cd {node_copy_path}")
                        logger.info(f"Attempted to change to directory {node_copy_path} on node {node[1]}.")

                        # Verify the current working directory
                        output = node_object.execute("pwd")
                        current_path = output.splitlines()[1].strip() 
                        if current_path != node_copy_path:
                            logger.warning(f"Directory {node_copy_path} does not exist on node {node[1]}. Attempting to create it.")
                            
                            # Create the directory and navigate to it
                            node_object.execute(f"mkdir -p {node_copy_path}")
                            node_object.execute(f"cd {node_copy_path}")
                            
                            # Verify again
                            current_path = node_object.execute("pwd").strip()
                            if current_path == node_copy_path:
                                logger.info(f"Successfully created and changed to directory {node_copy_path} on node {node[1]}.")
                            else:
                                logger.error(f"Failed to navigate to directory {node_copy_path} on node {node[1]}. Aborting operations for this node.")
                                raise RuntimeError(f"Unable to change to directory {node_copy_path}.")
                        else:
                            logger.info(f"Verified current directory: {current_path}")

                    except Exception as e:
                        logger.error(f"An error occurred while changing to or creating the directory {node_copy_path} on node {node[1]}: {e}")
                        final_dictionary[file] = f"Failed to create the core copy path for file: {file}"
                        continue


                    # Step 3: Copy the core file
                    try:
                        remote_path = extract_remote_path_from_nms_to_core(file, node, logs_path)
                        copy_core_from_nms_to_node(nms_host, nms_username, nms_password, remote_path, node_object)
                        logger.info(f"Copied core file to node {node[1]}.")
                    except Exception as e:
                        logger.error(f"Failed to copy core file for {file} to node {node[1]}: {e}")
                        final_dictionary[file]['gdb']  = f"Failed to copy core file for {file}"
                        continue

                    # Step 4: Untar the core file
                    try:
                        untar_all_core_file(node_object)
                        logger.info(f"Core file untarred on node {node[1]}.")
                    except Exception as e:
                        logger.error(f"Failed to untar core file for {file} on node {node[1]}: {e}")
                        final_dictionary[file]['gdb']  = f"Failed to untar core file for {file}"
                        continue

                    # Step 5: Get the core files list
                    corefiles_list = get_core_files(node_object)
                    if not corefiles_list:
                        logger.warning(f"No core files found for {file} on node {node[1]}. Skipping.")
                        final_dictionary[file] = f"No core files found for {file}. Skipping."
                        continue

                    # Step 6: Perform sector login
                    if not login_sector(sudo_password, file, node_object):
                        logger.error(f"Failed to perform sector login for {file}. Skipping.")
                        final_dictionary[file]['gdb']  = f"Failed to perform sector login for {file}"
                        continue

                    # Step 7: Change to gdb directory
                    node_object.execute(f"cd {gdb_run_path}")
                    logger.info(f"Changed to GDB directory {gdb_run_path} on node {node[1]}.")

                    # Step 8: Execute GDB commands and parse output
                    try:
                        gdb_dict = execute_gdb_commands_and_getData(
                            gdb_execute_commands, node_object, gdb_run_command, corefiles_list
                        )
                        parsed_gdb_output = parse_gdb_output(gdb_dict)
                        # final_dictionary[file]['gdb']  = parsed_gdb_output
                        gdb_output_dir = os.path.join(local_dir_path, "GDBdump")
                        parse_gdb_to_link(final_dictionary, parsed_gdb_output, gdb_output_dir, file)
                        logger.info(f"Processed GDB output for {file}.")
                    except Exception as e:
                        logger.error(f"Failed to execute GDB commands for {file}: {e}")
                        final_dictionary[file]['gdb']  = f"Failed to execute GDB commands for {file}"
                        node_object.execute("exit") # come out of sector
                        continue



                    # Step 9: Cleanup - Exit sector and clear core files
                    try:
                        node_object.execute('exit')  # Exit sector login
                        node_object.execute('clear')  # Clear terminal
                        node_object.execute(f"cd {node_copy_path}")
                        clear_core_files_in_node(node_object, corefiles_list)
                        logger.info(f"Cleared core files for {file} on node {node[1]}.")
                    except Exception as e:
                        logger.warning(f"Cleanup failed for {file} on node {node[1]}: {e}")

                    # Sleep to reduce load on the system
                    time.sleep(5)
                    print(final_dictionary)

                except Exception as e:
                    logger.error(f"An unexpected error occurred while processing {file}: {e}")
                    final_dictionary[file] = f"Error occurred: {e}"

                finally:
                    logger.info(f"{file} processing completed.")

        # Debugging: Check the final dictionary after processing
        pdb.set_trace()
        
        write_final_dictionary_to_csv(final_dictionary, local_dir_path)

        # Iterate through dictionary
        # for file, (node_object, sector) in node_connector_objects.items():
        #     process_node_file(file, node_object, sector, sudo_password, nms_host, nms_username, nms_password, remote_path, gdb_run_path, gdb_commands)

        # pdb.set_trace()

    except Exception as e:
        print(f"An error occurred in main: {e}")
    finally:
        print("Main execution completed.")


# if __name__ == "__main__":
#     main()


# Assuming you have helper functions defined elsewhere, e.g., load_json_input, connector, etc.
final_dictionary = {}

class MainProcessor:
    def __init__(self, input_data):
        self.input_data = input_data
        self.local_dir_path = ""
        self.node_ip_dictionary = {}
        self.final_dictionary = final_dictionary
        self.node_connector_objects = {}
        self.logger = logging.getLogger("MainProcessor")
        logging.basicConfig(level=logging.INFO)


    def load_inputs(self):
        try:
            self.start_date = self.input_data.get("start_date")
            self.start_time = self.input_data.get("start_time")
            self.end_date = self.input_data.get("end_date")
            self.end_time = self.input_data.get("end_time")
            self.nms_host = self.input_data.get("nms_host")
            self.nms_username = self.input_data.get("nms_username")
            self.nms_password = self.input_data.get("nms_password")
            self.dummy_node = self.input_data.get("dummy_node")
            self.node_username = self.input_data.get("node_username")
            self.node_password = self.input_data.get("node_password")
            self.sudo_password = self.input_data.get("sudo_password")
            self.node_copy_path = self.input_data.get("node_copy_path")
            self.gdb_run_path = self.input_data.get("gdb_run_path")
            self.gdb_run_command = self.input_data.get("gdb_run_command")
            self.gdb_execute_commands = self.input_data.get("gdb_execute_commands")
            self.remote_crash_dir = self.input_data.get("remote_crash_dir")
            self.logs_path = self.input_data.get("logs_path")
            self.parent_dir = self.input_data.get("parent_dir")

            # Add checks for required fields and logical conditions
            if not self.start_date or not self.start_time or not self.end_date or not self.end_time:
                self.logger.error("Start date and time, and end date and time must be provided.")
                return False

            if not self.nms_host or not self.nms_username or not self.nms_password:
                self.logger.error("NMS host, username, and password must be provided.")
                return False

            if not self.node_username or not self.node_password or not self.sudo_password:
                self.logger.error("Node credentials (username, password, sudo password) must be provided.")
                return False

            if not self.node_copy_path or not self.gdb_run_path or not self.gdb_run_command:
                self.logger.error("Node copy path, GDB run path, and GDB run command must be provided.")
                return False

            if not self.gdb_execute_commands or not isinstance(self.gdb_execute_commands, list):
                self.logger.error("GDB execute commands must be provided as a list.")
                return False

            if not self.remote_crash_dir or not self.logs_path or not self.parent_dir:
                self.logger.error("Paths for remote crash directory, logs, and parent directory must be provided.")
                return False

            # If all required fields pass checks
            self.logger.info("All inputs loaded successfully.")
            return True

        except Exception as e:
            self.logger.error(f"An error occurred while loading inputs: {e}")
            return False
        

    def setup_local_directory(self):
        start_datetime = datetime.strptime(
            f"{self.start_date} {self.start_time}", "%Y-%m-%d %H:%M")
        end_datetime = datetime.strptime(
            f"{self.end_date} {self.end_time}", "%Y-%m-%d %H:%M")

        dir_name = f"enc_untar_tool_{start_datetime.strftime('%Y%m%d_%H%M')}_to_{end_datetime.strftime('%Y%m%d_%H%M')}"
        parent_dir = self.parent_dir
        self.local_dir_path = os.path.join(parent_dir, dir_name)

        # Corrected logic to always create the directory if it doesn't exist
        os.makedirs(self.local_dir_path, exist_ok=True)
        self.logger.info(f"Directory created: {self.local_dir_path}")


    def search_and_process_files(self):
        nms_host = self.nms_host
        nms_username = self.nms_username
        nms_password = self.nms_password
        
        self.nms_object_communicator = connector(nms_host, nms_username, nms_password)
        logs_path = self.logs_path
        self.nms_object_communicator.execute(f"cd {logs_path}")

        start_datetime = datetime.strptime(
            f"{self.start_date} {self.start_time}", "%Y-%m-%d %H:%M")
        end_datetime = datetime.strptime(
            f"{self.end_date} {self.end_time}", "%Y-%m-%d %H:%M")

        start_str = start_datetime.strftime("%Y-%m-%d %H:%M")
        end_str = end_datetime.strftime("%Y-%m-%d %H:%M")
        files_list = self.nms_object_communicator.execute(
            f'find . -maxdepth 1 -type f -newermt "{start_str}" ! -newermt "{end_str}" -name "*.enc"'
        )
        process_file_line(files_list.splitlines()[1:], start_datetime, end_datetime, self.nms_object_communicator, self.local_dir_path)


    def untar_files(self):
        copy_crash_tool(self.nms_object_communicator, self.remote_crash_dir, self.local_dir_path)
        run_crash_untar_tool(self.local_dir_path)
        delete_enc_untar_in_directory(self.local_dir_path)

        
    def core_dump_fc_56(self):
        try:
            self.node_ip_dictionary = extract_management_server_ip(self.local_dir_path)
            # pdb.set_trace()
            self.logger.info("Processing FC_56 files in the local directory.")
            process_fc56_files(self.local_dir_path, self.node_ip_dictionary)
        except Exception as e:
            error_msg = f"FC_56 Processing Failed: {e}"
            self.logger.error(error_msg)
        # Step 6: Copy coredump from the local directory to the NMS server
        local_coredump_path = os.path.join(self.local_dir_path, 'CoreDump')
        try:
            self.logger.info(f"Copying coredump from {local_coredump_path} to NMS server.")
            copy_to_nms(
                local_coredump_path, 
                self.nms_host, 
                self.logs_path, 
                self.nms_username, 
                self.nms_password
            )
        except Exception as e:
            error_msg = f"CoreDump Copy to NMS Failed: {e}"
            self.logger.error(error_msg)

    def process_files_and_run_gdb(self):    
        # Process individual files
        self.node_connector_objects = process_node_connections(self.node_ip_dictionary, self.node_username, self.node_password)

        local_logsdump_path = os.path.join(self.local_dir_path, 'LogsDump')
        os.makedirs(local_logsdump_path, exist_ok=True)
        for file, (node_object, node_ip) in self.node_connector_objects.items():
            try:
                self.logger.info(f"Processing file: {file}")
                
                # Check for node connectivity
                if node_object is None:
                    self.final_dictionary[file] = "Node unreachable."
                    continue

                # Step 1: Analyze L2 initialization file if applicable
                sec_name_match = re.search(r"(SEC_\d)", file)
                if sec_name_match:
                    sec_name = sec_name_match.group(1)  # Extract sector name (e.g., SEC_1)
                    local_file_path = os.path.join(self.local_dir_path, file)
                    analyze_l2_init_file(local_file_path, sec_name, local_logsdump_path, file, self.final_dictionary)
                
                # Step 2: Initial sudo login to the node
                if not sudo_login(self.sudo_password, node_object):
                    logger.error(f"Failed to switch to sudo mode for node {node_ip}. Skipping.")
                    self.final_dictionary[file]['gdb']  = f"Failed to switch to sudo mode for node {node_ip}"
                    continue


                try:
                    # Step 2: Change to the working directory
                    node_object.execute(f"cd {self.node_copy_path}")
                    logger.info(f"Attempted to change to directory {self.node_copy_path} on node {node_ip}.")

                    # Verify the current working directory
                    output = node_object.execute("pwd")
                    current_path = output.splitlines()[1].strip() 
                    if current_path != self.node_copy_path:
                        logger.warning(f"Directory {self.node_copy_path} does not exist on node {node_ip}. Attempting to create it.")
                        
                        # Create the directory and navigate to it
                        node_object.execute(f"mkdir -p {self.node_copy_path}")
                        node_object.execute(f"cd {self.node_copy_path}")
                        
                        # Verify again
                        current_path = node_object.execute("pwd").strip()
                        if current_path == self.node_copy_path:
                            logger.info(f"Successfully created and changed to directory {self.node_copy_path} on node {node_ip}.")
                        else:
                            logger.error(f"Failed to navigate to directory {self.node_copy_path} on node {node_ip}. Aborting operations for this node.")
                            raise RuntimeError(f"Unable to change to directory {self.node_copy_path}.")
                    else:
                        logger.info(f"Verified current directory: {current_path}")

                except Exception as e:
                    logger.error(f"An error occurred while changing to or creating the directory {self.node_copy_path} on node {node_ip}: {e}")
                    self.final_dictionary[file] = f"Failed to create the core copy path for file: {file}"
                    continue

                # Step 3: Copy core file from NMS to node
                remote_path = extract_remote_path_from_nms_to_core(file, node_ip, self.logs_path)
                copy_core_from_nms_to_node(
                    self.nms_host, self.nms_username,
                    self.nms_password, remote_path, node_object
                )
                self.logger.info(f"Copied core file to node {node_ip}.")

                # Step 4: Untar the core file on the node
                untar_all_core_file(node_object)
                self.logger.info(f"Core file untarred on node {node_ip}.")

                # Step 5: Get the list of core files
                corefiles_list = get_core_files(node_object)
                if not corefiles_list:
                    self.logger.warning(f"No core files found for {file} on node {node_ip}. Skipping.")
                    self.final_dictionary[file] = f"No core files found for {file}. Skipping."
                    continue


                # Step 6: Perform sector login
                if not login_sector(self.sudo_password, file, node_object):
                    logger.error(f"Failed to perform sector login for {file}. Skipping.")
                    self.final_dictionary[file]['gdb']  = f"Failed to perform sector login for {file}"
                
                    continue
                # Step 6: Execute GDB commands and parse the output
                gdb_run_path = self.gdb_run_path
                gdb_run_command = self.gdb_run_command
                gdb_execute_commands = self.gdb_execute_commands
                                    # Step 7: Change to gdb directory
                node_object.execute(f"cd {gdb_run_path}")
                logger.info(f"Changed to GDB directory {gdb_run_path} on node {node_ip}.")

                gdb_output = execute_gdb_commands_and_getData(
                    gdb_execute_commands, node_object, gdb_run_command, corefiles_list
                )
                parsed_output = parse_gdb_output(gdb_output)

                # Step 7: Parse and store results in final dictionary
                gdb_output_dir = os.path.join(self.local_dir_path, "GDBdump")
                parse_gdb_to_link(self.final_dictionary, parsed_output, gdb_output_dir, file)
                self.logger.info(f"Finished GDB processing for {file}.")

                try:
                    node_object.execute('exit')  # Exit sector login
                    node_object.execute('clear')  # Clear terminal
                    node_object.execute(f"cd {self.node_copy_path}")
                    clear_core_files_in_node(node_object, corefiles_list)
                    logger.info(f"Cleared core files for {file} on node {node_ip}.")
                except Exception as e:
                    logger.warning(f"Cleanup failed for {file} on node {node_ip}: {e}")

            except Exception as e:
                self.logger.error(f"Error processing {file}: {e}")
                self.final_dictionary[file] = str(e)
            finally:
                # Cleanup and wait for next operation
                time.sleep(5)
                self.logger.info(f"{file} processing completed.")


    def finalize_results(self):
        write_final_dictionary_to_csv(self.final_dictionary, self.local_dir_path)
        


    def run(self):
        if not self.load_inputs():
            return
        self.setup_local_directory()
        self.search_and_process_files()
        self.untar_files()
        self.core_dump_fc_56()
        self.process_files_and_run_gdb()
        
        self.finalize_results()


# Execution
if __name__ == "__main__":
    json_file_path = "input.json"
    input_data = load_json_input(json_file_path)
    if not input_data:
        logger.error("Invalid input. Exiting.")
    processor = MainProcessor(input_data)
    processor.run()
    pdb.set_trace()
    
print(final_dictionary)
