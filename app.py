import platform
from flask import Flask, render_template, request
import uuid
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import json
from datetime import datetime, timedelta
import os

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

LICENSE_FILE = 'license_info.json'

def get_hardware_id():
    """
    Generate a hardware ID based on motherboard serial number and BIOS UUID or version.
    """
    motherboard_id = "unknown"
    bios_id = "unknown"

    # Platform-specific logic
    if platform.system() == "Windows" and wmi:
        try:
            # Use WMI to get motherboard and BIOS info on Windows
            c = wmi.WMI()
            # Motherboard serial number
            for board in c.Win32_BaseBoard():
                motherboard_id = board.SerialNumber.strip() if board.SerialNumber else "unknown"
            # BIOS UUID or version
            for bios in c.Win32_BIOS():
                bios_id = bios.SerialNumber.strip() or bios.SMBIOSBIOSVersion.strip() or "unknown"
        except Exception:
            pass
    else:
        # Fallback for unsupported platforms (e.g., macOS)
        motherboard_id = str(uuid.getnode())  # MAC address as a fallback
        bios_id = platform.machine()  # Machine architecture as a fallback

    # Combine the parameters into a raw ID
    raw_id = f"{motherboard_id}-{bios_id}"

    # Generate a 16-character SHA-256 hash
    return hashlib.sha256(raw_id.encode()).hexdigest()[:16]

def save_license_info(expiration_date):
    license_info = {'expiration': expiration_date.strftime('%Y-%m-%d')}
    with open(LICENSE_FILE, 'w') as f:
        json.dump(license_info, f)

def load_license_info():
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            license_info = json.load(f)
            return datetime.strptime(license_info['expiration'], '%Y-%m-%d')
    return None

def validate_license(license_key):
    try:
        # Decode the base64 license key
        decoded_license = base64.b64decode(license_key.strip())
        
        # Extract signature length (first 4 bytes)
        signature_length = int.from_bytes(decoded_license[:4], byteorder='big')
        
        # Extract signature and license data
        signature = decoded_license[4:4+signature_length]
        license_data = decoded_license[4+signature_length:]
        
        # Load and verify with public key
        public_key = serialization.load_pem_public_key(PUBLIC_KEY.encode(), backend=default_backend())
        public_key.verify(
            signature,
            license_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # Decode JSON data
        license_dict = json.loads(license_data.decode('utf-8'))

        # Check hardware ID
        if license_dict['hardware_id'] != get_hardware_id():
            return False, "License is not valid for this machine."

        # Check or set expiration
        stored_expiration = load_license_info()
        if stored_expiration is None:
            duration_days = int(license_dict['duration_days'])
            expiration_date = datetime.now() + timedelta(days=duration_days)
            save_license_info(expiration_date)
            return True, f"License activated! Valid until {expiration_date.strftime('%Y-%m-%d')}."
        else:
            if stored_expiration < datetime.now():
                return False, "License has expired."
            return True, f"License is valid until {stored_expiration.strftime('%Y-%m-%d')}."

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

    if request.method == 'POST':
        license_key = request.form.get('license_key')
        if license_key:
            is_valid, message = validate_license(license_key)
    
    return render_template('index.html', hardware_id=hardware_id, message=message)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
