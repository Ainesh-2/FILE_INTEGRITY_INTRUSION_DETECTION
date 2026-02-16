import hashlib


def hash_file(input_string):    
    hash256 = hashlib.sha256()
    try:
        with open(input_string, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hash256.update(chunk)
        return hash256.hexdigest()
    except Exception as error:
        print(f"Error hashing file: {input_string}:", error)
        return None
