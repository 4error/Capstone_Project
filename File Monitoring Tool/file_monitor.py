#!/usr/bin/python3
import os
import sys
import time
import pwd
import csv
import signal
import argparse
from datetime import datetime
import pyinotify

#Global variables
RUNNING = True
LOG_FILE = "/var/log/file_monitor.csv"  #Default system-wide log location
DEFAULT_MONITOR_PATHS = ["/home", "/var/www", "/etc"]  #Default paths to monitor

def signal_handler(sig, frame):
    """Handle termination signals gracefully"""
    global RUNNING
    print(f"Received signal {sig}, shutting down...")
    RUNNING = False

def create_csv_log_file(log_file):
    """Create or validate the CSV log file with proper headers"""
    #Check if file already exists
    file_exists = os.path.isfile(log_file)
    
    try:
        #Open in append mode to preserve existing data
        with open(log_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                #Add headers for new file
                writer.writerow(['timestamp', 'date', 'time', 'username', 'operation', 'file_path', 'monitored_path'])
                print(f"Created new log file: {log_file}")
            else:
                print(f"Using existing log file: {log_file}")
    except PermissionError:
        print(f"Error: Permission denied when writing to {log_file}")
        print("Try running with sudo or specify a different log file location.")
        sys.exit(1)

#Event handler class for file monitoring
class SmartMonitorHandler(pyinotify.ProcessEvent):
    def __init__(self, target_dir, log_file):
        #Initialize with target directory
        self.target_dir = os.path.abspath(target_dir)
        self.log_file = log_file
        
    #Define handlers for different file system events
    def process_IN_CREATE(self, event):
        self._process_event(event, "create")
    
    def process_IN_DELETE(self, event):
        self._process_event(event, "delete")
    
    def process_IN_MODIFY(self, event):
        self._process_event(event, "modify")
    
    def process_IN_MOVED_FROM(self, event):
        self._process_event(event, "moved_from")
    
    def process_IN_MOVED_TO(self, event):
        self._process_event(event, "moved_to")
    
    def process_IN_CLOSE_WRITE(self, event):
        self._process_event(event, "write")
    
    def _process_event(self, event, operation_type):
        """Common processing logic for all event types"""
        #Get username by file ownership
        try:
            if os.path.exists(event.pathname):
                #For existing files, get owner directly
                stat_info = os.stat(event.pathname)
                uid = stat_info.st_uid
                try:
                    username = pwd.getpwuid(uid).pw_name
                except KeyError:
                    username = f"uid-{uid}"
            else:
                #For deleted files, use parent directory's owner
                parent_dir = os.path.dirname(event.pathname)
                stat_info = os.stat(parent_dir)
                uid = stat_info.st_uid
                try:
                    username = pwd.getpwuid(uid).pw_name
                except KeyError:
                    username = f"uid-{uid}"
        except Exception:
            username = "unknown"
        
        #Get timestamp with separate date and time for filtering
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")
        
        #Smart path formatting based on location
        if self.target_dir == event.pathname or os.path.dirname(event.pathname) == self.target_dir:
            #Direct file in the monitored directory - show just filename
            filename = os.path.basename(event.pathname)
        else:
            #For other files, show relative path from target dir if possible
            try:
                rel_path = os.path.relpath(event.pathname, self.target_dir)
                if rel_path.startswith(".."):
                    #Outside target directory
                    filename = event.pathname
                else:
                    filename = rel_path
            except:
                filename = event.pathname
        
        #Log event to CSV file
        try:
            with open(self.log_file, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, date_str, time_str, username, operation_type, filename, self.target_dir])
        except Exception as e:
            print(f"Error writing to log file: {e}")

def monitor_directory(target_dir, log_file, verbose=False):
    """Monitor a single directory for file changes"""
    if verbose:
        print(f"Starting monitoring for: {target_dir}")
    
    #Set up pyinotify components
    wm = pyinotify.WatchManager()
    
    #Specify which events to monitor
    mask = (pyinotify.IN_CREATE | pyinotify.IN_DELETE | 
            pyinotify.IN_MODIFY | pyinotify.IN_MOVED_FROM | 
            pyinotify.IN_MOVED_TO | pyinotify.IN_CLOSE_WRITE)
    
    #Create event handler and notifier
    handler = SmartMonitorHandler(target_dir, log_file)
    notifier = pyinotify.Notifier(wm, handler)
    
    #Add recursive watch on target directory
    try:
        wdd = wm.add_watch(target_dir, mask, rec=True, auto_add=True)
        
        #Verify watch was added successfully
        if target_dir not in wdd or wdd[target_dir] <= 0:
            print(f"Error: Failed to set up watch for {target_dir}")
            return None
        
        if verbose:
            print(f"Successfully set up watch for {target_dir}")
        
        return notifier
    except Exception as e:
        print(f"Error setting up watch for {target_dir}: {e}")
        return None

def run_background_monitor(paths, log_file, verbose=False):
    """Run monitoring in background mode for multiple paths"""
    global RUNNING
    
    #Set up signal handlers for graceful termination
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    #Create or validate log file
    create_csv_log_file(log_file)
    
    if verbose:
        print(f"File Monitor Service starting...")
        print(f"Logging to: {log_file}")
    
    #Set up notifiers for each path
    notifiers = []
    for path in paths:
        if os.path.isdir(path):
            notifier = monitor_directory(path, log_file, verbose)
            if notifier:
                notifiers.append(notifier)
        else:
            print(f"Warning: {path} is not a valid directory. Skipping.")
    
    if not notifiers:
        print("Error: No valid directories to monitor. Exiting.")
        return
    
    if verbose:
        print(f"Monitoring {len(notifiers)} directories. Running in background mode.")
    
    #Main monitoring loop
    try:
        while RUNNING:
            for notifier in notifiers:
                notifier.process_events()
                if notifier.check_events(timeout=100):  #Short timeout to check all notifiers
                    notifier.read_events()
            
            #Small sleep to prevent CPU hogging
            time.sleep(0.1)
    except Exception as e:
        print(f"Error in monitoring loop: {e}")
    finally:
        #Clean up resources
        for notifier in notifiers:
            notifier.stop()
        if verbose:
            print("File monitoring stopped.")

def main():
    """Main program entry point"""
    #Parse command line arguments
    parser = argparse.ArgumentParser(description="File Monitoring Service")
    parser.add_argument('--paths', nargs='+', default=DEFAULT_MONITOR_PATHS,
                      help='Paths to monitor (space-separated)')
    parser.add_argument('--log', default=LOG_FILE,
                      help='Location of the log file')
    parser.add_argument('--verbose', action='store_true',
                      help='Print verbose output')
    
    args = parser.parse_args()
    
    #Run in background monitoring mode
    run_background_monitor(args.paths, args.log, args.verbose)

#Program entry point
if __name__ == "__main__":
    main()
