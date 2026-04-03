import yara
import os

def scan_file_with_yara(file_path, rules_dir):
    try:
        # Compile YARA rules from the directory
        rules = yara.compile(filepaths={f.replace('.yar', ''): os.path.join(rules_dir, f) for f in os.listdir(rules_dir) if f.endswith('.yar')})
        
        # Scan the file
        matches = rules.match(file_path)
        
        if matches:
            print(f"Matches found for {file_path}:")
            for match in matches:
                print(f"  Rule: {match.rule}, Tags: {match.tags}, Meta: {match.meta}")
        else:
            print(f"No YARA matches found for {file_path}.")
            
    except yara.Error as e:
        print(f"YARA Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Create a dummy file for scanning
    dummy_file_path = "/home/ubuntu/dummy_malware.txt"
    with open(dummy_file_path, "w") as f:
        f.write("This is a test file containing some suspicious string related to anatova ransomware.")

    yara_rules_directory = "/home/ubuntu/yara_rules"
    
    print(f"Scanning {dummy_file_path} using rules from {yara_rules_directory}...")
    scan_file_with_yara(dummy_file_path, yara_rules_directory)

    # Clean up the dummy file
    os.remove(dummy_file_path)


