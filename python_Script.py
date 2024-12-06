import re
import csv
from collections import Counter

def count_requests_per_ip(log_file_path):
    with open(log_file_path, 'r') as file:
        log_data = file.readlines()
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_addresses = [re.search(ip_pattern, line).group() for line in log_data if re.search(ip_pattern, line)]
    ip_count = Counter(ip_addresses)
    sorted_ip_counts = ip_count.most_common()
    print("IP Address           Request Count")
    print("-" * 40)
    for ip, count in sorted_ip_counts:
        print(f"{ip:<20}{count}")
    return sorted_ip_counts

def most_frequent_endpoint(log_file_path):
    with open(log_file_path, 'r') as file:
        log_data = file.readlines()
    endpoint_pattern = r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\/\S*)'
    endpoints = [re.findall(endpoint_pattern, line)[0] for line in log_data if re.findall(endpoint_pattern, line)]
    endpoint_count = Counter(endpoints)
    most_frequent = max(endpoint_count.items(), key=lambda x: x[1]) if endpoint_count else None
    if most_frequent:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_frequent[0]} (Accessed {most_frequent[1]} times)")
    return most_frequent

def detect_suspicious_activity(log_file_path, threshold=10):
    with open(log_file_path, 'r') as file:
        log_data = file.readlines()
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    failed_login_pattern = r'(401|Invalid credentials)'
    failed_attempts = [re.search(ip_pattern, line).group() for line in log_data if re.search(failed_login_pattern, line) and re.search(ip_pattern, line)]
    failed_count = Counter(failed_attempts)
    flagged_ips = [(ip, count) for ip, count in failed_count.items() if count > threshold]
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    print("-" * 40)
    if flagged_ips:
        for ip, count in flagged_ips:
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    return flagged_ips

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity):
    with open("log_analysis_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow(most_accessed_endpoint)
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)

if __name__ == "__main__":
    log_file_path = "C:\\Users\\HP\\Desktop\\file.log"
    ip_counts = count_requests_per_ip(log_file_path)
    most_accessed_endpoint = most_frequent_endpoint(log_file_path)
    suspicious_activity = detect_suspicious_activity(log_file_path, threshold=10)
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)
