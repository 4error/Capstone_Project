#!/usr/bin/python3
import os
import sys
import csv
import argparse
from datetime import datetime

#Default log file location (same as monitor script)
DEFAULT_LOG_FILE = "/var/log/file_monitor.csv"

def query_log_file(log_file, filters, output_format="text"):
    """Query the log file based on specified filters"""
    #Check file existence
    if not os.path.exists(log_file):
        print(f"Error: Log file {log_file} does not exist.")
        return
    
    #Display query parameters
    print("\nQuerying log file for events:")
    
    if filters.get("start_time"):
        print(f"- From: {filters['start_time']}")
    if filters.get("end_time"):
        print(f"- To: {filters['end_time']}")
    if filters.get("user"):
        print(f"- User: {filters['user']}")
    if filters.get("operation"):
        print(f"- Operation: {filters['operation']}")
    if filters.get("date"):
        print(f"- Date: {filters['date']}")
    if filters.get("path"):
        print(f"- Path contains: {filters['path']}")
    if filters.get("monitor_path"):
        print(f"- Monitored path: {filters['monitor_path']}")
    if not filters:
        print("- All events")
    
    #Format for results
    print("\nResults:")
    print("-" * 100)
    
    #Process log file and apply filters
    count = 0
    matching_events = []
    
    try:
        with open(log_file, mode='r', newline='') as f:
            reader = csv.DictReader(f)
            
            #Check if CSV has required fields
            if not all(field in reader.fieldnames for field in ['date', 'time', 'username', 'operation', 'file_path']):
                print(f"Error: Log file {log_file} does not have the expected format.")
                return
                
            for row in reader:
                #Apply time range filter
                if filters.get("start_time") and filters.get("end_time"):
                    #Check if time is within range
                    if not (filters["start_time"] <= row['time'] <= filters["end_time"]):
                        continue
                elif filters.get("start_time"):
                    if not (filters["start_time"] <= row['time']):
                        continue
                elif filters.get("end_time"):
                    if not (row['time'] <= filters["end_time"]):
                        continue
                
                #Apply date filter
                if filters.get("date") and row['date'] != filters["date"]:
                    continue
                
                #Apply username filter
                if filters.get("user") and row['username'] != filters["user"]:
                    continue
                
                #Apply operation type filter
                if filters.get("operation") and row['operation'] != filters["operation"]:
                    continue
                
                #Apply path substring filter
                if filters.get("path") and filters["path"].lower() not in row['file_path'].lower():
                    continue
                
                #Apply monitored path filter
                if filters.get("monitor_path") and 'monitored_path' in row:
                    if filters["monitor_path"] != row['monitored_path']:
                        continue
                
                #Store matching record for output
                matching_events.append(row)
                
                #Display in text format
                if output_format == "text":
                    print(f"[{row['date']} {row['time']}] User: {row['username']} | Operation: {row['operation']} | File: {row['file_path']}")
                
                count += 1
    
    except Exception as e:
        print(f"Error reading log file: {e}")
        return
    
    #Output in different formats if requested
    if output_format == "csv" and matching_events:
        output_file = "query_results.csv"
        try:
            with open(output_file, mode='w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=matching_events[0].keys())
                writer.writeheader()
                writer.writerows(matching_events)
            print(f"\nResults saved to {output_file}")
        except Exception as e:
            print(f"Error writing CSV output: {e}")
    
    #Display summary
    print("-" * 100)
    print(f"Found {count} matching events")

def interactive_query(log_file):
    """Interactive query interface"""
    #Validate log file existence
    if not os.path.exists(log_file):
        print(f"Error: Log file {log_file} does not exist.")
        return
    
    #Display header
    print("\n" + "=" * 60)
    print("           Log Query Tool")
    print("=" * 60)
    print(f"Analyzing log file: {log_file}")
    
    #Main query menu loop
    while True:
        print("\nQuery options:")
        print("1. Query by time range")
        print("2. Query by username")
        print("3. Query by operation type")
        print("4. Query by date")
        print("5. Query by file path")
        print("6. Query by monitored directory")
        print("7. Combined query")
        print("8. Show all logs")
        print("9. Exit query mode")
        
        try:
            choice = int(input("\nEnter your choice (1-9): "))
            
            if choice == 1:
                #Time range query
                start_time = input("Enter start time (HH:MM:SS): ")
                end_time = input("Enter end time (HH:MM:SS): ")
                query_log_file(log_file, {"start_time": start_time, "end_time": end_time})
            
            elif choice == 2:
                #Username query
                username = input("Enter username: ")
                query_log_file(log_file, {"user": username})
            
            elif choice == 3:
                #Operation type query
                print("\nOperation types: create, modify, delete, write, moved_from, moved_to")
                operation = input("Enter operation type: ")
                query_log_file(log_file, {"operation": operation})
            
            elif choice == 4:
                #Date query
                date = input("Enter date (YYYY-MM-DD): ")
                query_log_file(log_file, {"date": date})
            
            elif choice == 5:
                #File path query
                path = input("Enter file path (or part of path): ")
                query_log_file(log_file, {"path": path})
            
            elif choice == 6:
                #Monitored directory query
                path = input("Enter monitored directory: ")
                query_log_file(log_file, {"monitor_path": path})
            
            elif choice == 7:
                #Combined query with multiple filters
                print("\nLeave blank to skip any filter")
                date = input("Date (YYYY-MM-DD): ")
                start_time = input("Start time (HH:MM:SS): ")
                end_time = input("End time (HH:MM:SS): ")
                username = input("Username: ")
                operation = input("Operation type: ")
                path = input("File path contains: ")
                monitor_path = input("Monitored directory: ")
                
                #Build filters dictionary with only non-empty values
                filters = {}
                if date:
                    filters["date"] = date
                if start_time:
                    filters["start_time"] = start_time
                if end_time:
                    filters["end_time"] = end_time
                if username:
                    filters["user"] = username
                if operation:
                    filters["operation"] = operation
                if path:
                    filters["path"] = path
                if monitor_path:
                    filters["monitor_path"] = monitor_path
                
                #Ask for output format
                print("\nOutput format:")
                print("1. Text (display on screen)")
                print("2. CSV file")
                format_choice = input("Choose format (1-2, default 1): ")
                
                output_format = "text"
                if format_choice == "2":
                    output_format = "csv"
                
                query_log_file(log_file, filters, output_format)
            
            elif choice == 8:
                #Show all logs (no filters)
                query_log_file(log_file, {})
            
            elif choice == 9:
                #Exit query mode
                print("Exiting query mode.")
                return
            
            else:
                print("Invalid choice. Please enter a number between 1 and 9.")
        
        except ValueError:
            #Handle non-numeric input
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled. Returning to main menu.")

def main():
    """Main program entry point"""
    #Parse command line arguments
    parser = argparse.ArgumentParser(description="File Monitor Log Query Tool")
    parser.add_argument('--log', default=DEFAULT_LOG_FILE,
                      help='Location of the log file to query')
    parser.add_argument('--date', help='Filter by date (YYYY-MM-DD)')
    parser.add_argument('--user', help='Filter by username')
    parser.add_argument('--operation', help='Filter by operation type')
    parser.add_argument('--path', help='Filter by file path (substring)')
    parser.add_argument('--output', choices=['text', 'csv'], default='text',
                      help='Output format (text or csv)')
    parser.add_argument('--interactive', action='store_true',
                      help='Run in interactive mode')
    
    args = parser.parse_args()
    
    #Check if we should run in interactive mode
    if args.interactive:
        interactive_query(args.log)
        return
    
    #Build filters from command-line arguments
    filters = {}
    if args.date:
        filters["date"] = args.date
    if args.user:
        filters["user"] = args.user
    if args.operation:
        filters["operation"] = args.operation
    if args.path:
        filters["path"] = args.path
    
    #If no filters provided but not interactive, default to interactive mode
    if not filters and not args.interactive:
        print("No filters provided. Starting interactive mode.")
        interactive_query(args.log)
    else:
        #Run query with provided filters
        query_log_file(args.log, filters, args.output)

#Program entry point
if __name__ == "__main__":
    main()
