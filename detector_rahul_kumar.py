import sys
import csv
import json
import re

# \b ensures we match whole numbers only.
REGEX_PATTERNS = {
    "aadhar": re.compile(r'\b\d{12}\b'),
    "phone": re.compile(r'\b\d{10}\b'),
    "passport": re.compile(r'\b[A-Z][0-9]{7}\b')
}

# Keys that are considered PII only when two or more are present in a record.
COMBINATORIAL_KEYS = [
    "name", "email", "address", "ip_address", "device_id"
]

# regex for validating and identifying email formats.
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')


def mask_pii_value(key, value):
    """Redacts a value based on the type of PII it is."""
    if not isinstance(value, str):
        value = str(value)

    if key == "phone" and len(value) == 10:
        return f"{value[:2]}{'X'*6}{value[-2:]}"
    elif key == "aadhar" and len(value) == 12:
        return f"{'X'*8}{value[-4:]}"
    elif key == "name":
        # Example of a more sophisticated name mask
        parts = value.split()
        if len(parts) > 1:
            return f"{parts[0][0]}{'X'*(len(parts[0])-1)} {parts[-1][0]}{'X'*(len(parts[-1])-1)}"
    
    # a generic redaction format for all other PII types
    return f"[REDACTED_{key.upper()}]"


def process_record(data_dict):
    """
    Analyzes a dictionary for PII and returns the redaction results.

    Args:
        data_dict (dict): The dictionary parsed from a single record's JSON.

    Returns:
        tuple: (is_pii, redacted_dict)
               - is_pii (bool): True if PII was found.
               - redacted_dict (dict): The dictionary with PII values masked.
    """
    is_pii = False
    redacted_dict = data_dict.copy()
    keys_to_redact = set()

    # 1. Check for standalone PII (Phone, Aadhar, Passport, UPI ID)
    for key, value in data_dict.items():
        if key == "upi_id":
            is_pii = True
            keys_to_redact.add(key)
            continue
        
        if isinstance(value, str):
            for pii_type, pattern in REGEX_PATTERNS.items():
                if pii_type in key and pattern.search(value):
                     is_pii = True
                     keys_to_redact.add(key)

    # 2. Check for combinatorial PII (Name, Email, Address, etc.)
    combinatorial_keys_found = []
    for key in data_dict:
        if key in COMBINATORIAL_KEYS:
            # Special check for email format to reduce false positives
            if key == 'email':
                if isinstance(data_dict[key], str) and EMAIL_REGEX.match(data_dict[key]):
                    combinatorial_keys_found.append(key)
            else:
                combinatorial_keys_found.append(key)

    if len(combinatorial_keys_found) >= 2:
        is_pii = True
        keys_to_redact.update(combinatorial_keys_found)
            
    # 3. If any PII was found, perform the redaction
    if is_pii:
        for key in keys_to_redact:
            if key in redacted_dict:
                redacted_dict[key] = mask_pii_value(key, redacted_dict[key])

    return is_pii, redacted_dict


def main(input_file, output_file):
    """Main function to read, process, and write the CSV data."""
    try:
        with open(input_file, mode='r', encoding='utf-8') as infile, \
             open(output_file, mode='w', encoding='utf-8', newline='') as outfile:

            reader = csv.DictReader(infile)
            fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                data_json_str = row.get('data_json', '{}')
                
                try:
                    # The provided CSV uses escaped quotes ("") inside the JSON string
                    cleaned_json_str = data_json_str.replace('""', '"')
                    data = json.loads(cleaned_json_str)
                except json.JSONDecodeError:
                    data = {} # Handle malformed JSON gracefully

                is_pii, redacted_data = process_record(data)

                writer.writerow({
                    'record_id': row.get('record_id'),
                    'redacted_data_json': json.dumps(redacted_data),
                    'is_pii': is_pii
                })

        print(f"Processing complete. Output saved to {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file not found")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_solution.py <input_csv_file>")
        sys.exit(1)

    input_csv_path = sys.argv[1]
    # As per the prompt's deliverable naming convention
    output_csv_path = "redacted_output_rahul_kumar.csv"
    main(input_csv_path, output_csv_path)
