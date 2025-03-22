import platform
from flask import Flask, render_template, request
import uuid
import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
from datetime import datetime

# Optional WMI import for Windows (install with 'pip install wmi')
try:
    import wmi
except ImportError:
    wmi = None

app = Flask(__name__)

# Replace with your actual public key from admin tool
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1hdLIznpqDxZqpHcW3+F
9a0tipB73DFvX/m3ITE3Ot52UwE1GWrkM4fJAb6c77fboSKnlEtq6iNWpXeKyatL
uUmxZeX1xb+GHGCqnvP/gvqnvQ+Qvh6RxVayAVpV6QS5rb+mGa+W1shw+eZU9aOm
3Xm0I80fHeIBe5oZ6C2sK27wD6SnCBzQ+1RPwIoC2vb50njbejYACOx7K94pp+iP
urSwK0r9MxFAyuwtANLFudp7u0h6mSAK7PRgJPJikIxNg062jXpqIzJuFZnXlbqE
i8JBefFHjrJGvOa+of6BvFPPNIafOjSlJpHgyCzsEk2ejNpFsG2BVj26oqT4kutI
TwIDAQAB
-----END PUBLIC KEY-----
"""

# The AES key must be the same as used on the admin side
# In a real-world scenario, this key would be securely distributed with your software
AES_KEY = bytes.fromhex('08bfb5a91d43c4d48600fee85fed9cfe52f945dcca1533a328cd2a1b1ef2942f')  # Example key - REPLACE THIS

LICENSE_FILE = 'license_info.json'
def get_hardware_id():
    """
    Generate a stable hardware ID for Windows systems that works in both script and executable modes.
    Uses multiple hardware identifiers with fallbacks for maximum reliability.
    """
    import subprocess
    import re
    import os
    import uuid
    import hashlib
    import ctypes
    from ctypes import windll, wintypes
    
    hardware_identifiers = []
    
    # Get Volume Serial Number (very stable - only changes if drive is reformatted)
    try:
        # Get system drive (usually C:)
        system_drive = os.environ.get('SystemDrive', 'C:')
        
        # Use WinAPI to get volume serial number
        volume_name_buffer = ctypes.create_unicode_buffer(1024)
        filesystem_name_buffer = ctypes.create_unicode_buffer(1024)
        serial_number = wintypes.DWORD(0)
        
        result = windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(system_drive + '\\'),
            volume_name_buffer,
            ctypes.sizeof(volume_name_buffer),
            ctypes.byref(serial_number),
            None,
            None,
            filesystem_name_buffer,
            ctypes.sizeof(filesystem_name_buffer)
        )
        
        if result != 0:
            volume_serial = f"{serial_number.value:08X}"
            hardware_identifiers.append(f"vol:{volume_serial}")
    except Exception:
        pass
    
    # Get CPU ID (very stable - only changes if CPU is replaced)
    try:
        wmic_output = subprocess.check_output(
            "wmic cpu get processorid", 
            shell=True, 
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        # Extract the processor ID
        match = re.search(r'ProcessorId\s*\n\s*([^\s,]+)', wmic_output, re.IGNORECASE)
        if match and match.group(1):
            cpu_id = match.group(1).strip()
            hardware_identifiers.append(f"cpu:{cpu_id}")
    except Exception:
        pass
    
    # Get motherboard serial (very stable - tied to physical hardware)
    try:
        wmic_output = subprocess.check_output(
            "wmic baseboard get serialnumber", 
            shell=True, 
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        # Extract the serial number
        match = re.search(r'SerialNumber\s*\n\s*([^\s,]+)', wmic_output, re.IGNORECASE)
        if match and match.group(1) and match.group(1).strip() not in ('None', 'To be filled by O.E.M.'):
            mb_serial = match.group(1).strip()
            hardware_identifiers.append(f"mb:{mb_serial}")
    except Exception:
        pass
    
    # Get BIOS serial as fallback
    try:
        wmic_output = subprocess.check_output(
            "wmic bios get serialnumber", 
            shell=True, 
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        # Extract the serial number
        match = re.search(r'SerialNumber\s*\n\s*([^\s,]+)', wmic_output, re.IGNORECASE)
        if match and match.group(1) and match.group(1).strip() not in ('None', 'To be filled by O.E.M.'):
            bios_serial = match.group(1).strip()
            hardware_identifiers.append(f"bios:{bios_serial}")
    except Exception:
        pass
    
    # MAC address as additional identifier
    try:
        mac = uuid.getnode()
        # Only use if it's not a random MAC (check if the locally administered bit is not set)
        if not (mac & 0x020000000000):
            mac_str = ':'.join(['{:02x}'.format((mac >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1])
            hardware_identifiers.append(f"mac:{mac_str}")
    except Exception:
        pass
    
    # Fallback to machine name if everything else fails
    if not hardware_identifiers:
        try:
            import socket
            hardware_identifiers.append(f"name:{socket.gethostname()}")
        except Exception:
            # Last resort - use a combination of system info
            import platform
            hardware_identifiers.append(f"sys:{platform.system()}_{platform.machine()}_{os.getenv('USERNAME')}")
    
    # Create a combined hardware string and hash it
    combined_hardware = "||".join(hardware_identifiers)
    
    # Return a 16-character SHA-256 hash
    return hashlib.sha256(combined_hardware.encode()).hexdigest()[:16]
    
def save_license_info(license_dict):
    """Save the license information to a local file."""
    with open(LICENSE_FILE, 'w') as f:
        json.dump(license_dict, f)

def load_license_info():
    """Load the license information from the local file."""
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            return json.load(f)
    return None

def decrypt_data(encrypted_data):
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    actual_data = encrypted_data[16:]
    
    # Create a decryptor
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(actual_data) + decryptor.finalize()
    
    # Remove padding (null bytes)
    return decrypted_data.rstrip(b'\x00')

def validate_license(license_key):
    try:
        # Decode the base64 license key
        decoded_license = base64.b64decode(license_key.strip())
        
        # Decrypt the data
        try:
            decrypted_data = decrypt_data(decoded_license)
        except Exception as e:
            return False, f"Error decrypting license key: {str(e)}"
        
        # Extract signature length (first 4 bytes)
        signature_length = int.from_bytes(decrypted_data[:4], byteorder='big')
        
        # Extract signature and license data
        signature = decrypted_data[4:4+signature_length]
        license_data = decrypted_data[4+signature_length:]
        
        # Load and verify with public key
        public_key = serialization.load_pem_public_key(PUBLIC_KEY.encode(), backend=default_backend())
        try:
            public_key.verify(
                signature,
                license_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception:
            return False, "License signature verification failed."

        # Decode JSON data
        license_dict = json.loads(license_data.decode('utf-8'))

        # Check hardware ID
        if license_dict['hardware_id'] != get_hardware_id():
            return False, "License is not valid for this machine."

        # Get expiration date from license data
        expiration_date = datetime.strptime(license_dict['expiration_date'], '%Y-%m-%d')
        
        # Check license expiration
        if expiration_date < datetime.now():
            return False, "License has expired."
        
        # Save license info locally (could be used for offline validation)
        save_license_info(license_dict)
        
        return True, f"License is valid until {license_dict['expiration_date']}."

    except base64.binascii.Error:
        return False, "Invalid license key format. Ensure it's a valid base64 string."
    except ValueError as e:
        return False, f"Error processing license key: {str(e)}"
    except Exception as e:
        return False, f"Invalid license key: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    hardware_id = get_hardware_id()
    message = None
    license_status = None
    expiration_date = None
    
    # Check for existing license
    license_info = load_license_info()
    if license_info:
        try:
            # Check if license is for this hardware
            if license_info['hardware_id'] == hardware_id:
                expiration_date = license_info['expiration_date']
                exp_date_obj = datetime.strptime(expiration_date, '%Y-%m-%d')
                
                # Check if license is valid
                if exp_date_obj >= datetime.now():
                    license_status = "Valid"
                    message = f"Licensed until {expiration_date}."
                else:
                    license_status = "Expired"
                    message = f"License expired on {expiration_date}."
        except Exception as e:
            message = f"Error reading license information: {str(e)}"

    if request.method == 'POST':
        license_key = request.form.get('license_key')
        if license_key:
            is_valid, message = validate_license(license_key)
            license_status = "Valid" if is_valid else "Invalid"
    
    return render_template('index.html', 
                          hardware_id=hardware_id, 
                          message=message,
                          license_status=license_status,
                          expiration_date=expiration_date)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)