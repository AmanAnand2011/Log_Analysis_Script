# Log Analysis Script
Overview

This Python script processes web server log files to extract and analyze key information. It performs three main tasks:

Counts Requests per IP Address: Identifies all IP addresses from the log file and counts the number of requests made by each IP.
Finds the Most Frequently Accessed Endpoint: Extracts the URLs or resource paths and identifies the one accessed the most.
Detects Suspicious Activity: Flags IP addresses with excessive failed login attempts (e.g., HTTP status code 401 or "Invalid credentials") based on a configurable threshold.
The results are displayed in the terminal and saved to a CSV file (log_analysis_results.csv) for easy reference.
