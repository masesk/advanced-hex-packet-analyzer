from flask import Flask, request, jsonify, Response, render_template
import binascii
import tempfile
import os
import subprocess
from xml.etree import ElementTree as ET

app = Flask(__name__, static_url_path="/static")

def hex_to_pcap(hex_string):
    """
    Convert hex string to pcap bytes
    Returns bytes object containing pcap data
    """
    # Remove any spaces or newlines from hex string
    hex_string = ''.join(hex_string.split())
    
    # Convert hex string to binary
    try:
        packet_bytes = binascii.unhexlify(hex_string)
    except binascii.Error as e:
        raise ValueError(f"Invalid hex string: {e}")
    
    # Basic pcap file header (24 bytes)
    pcap_global_header = (
        b'\xd4\xc3\xb2\xa1'  # magic number
        b'\x02\x00'         # major version
        b'\x04\x00'         # minor version
        b'\x00\x00\x00\x00' # timezone
        b'\x00\x00\x00\x00' # sigfigs
        b'\xff\xff\x00\x00' # snaplen (65535)
        b'\x01\x00\x00\x00' # link-layer header type (1 = Ethernet)
    )
    
    # Packet header (16 bytes per packet)
    timestamp_sec = 0
    timestamp_usec = 0
    pkt_len = len(packet_bytes)
    
    pcap_packet_header = (
        timestamp_sec.to_bytes(4, 'little') +
        timestamp_usec.to_bytes(4, 'little') +
        pkt_len.to_bytes(4, 'little') +
        pkt_len.to_bytes(4, 'little')
    )
    
    return pcap_global_header + pcap_packet_header + packet_bytes

def parse_packet_to_xml(hex_packet):
    """
    Parse packet hex string and output as XML using tshark
    """
    tmp_file_path = None
    try:
        # Convert hex to pcap bytes
        pcap_data = hex_to_pcap(hex_packet)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
            tmp_file.write(pcap_data)
            tmp_file_path = tmp_file.name
        
        # Use tshark directly
        tshark_cmd = [
            'tshark',
            '-r', tmp_file_path,  # Read from file
            '-T', 'pdml'          # Output in PDML (XML) format
        ]
        
        # Run tshark command
        result = subprocess.run(
            tshark_cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Get the XML output
        xml_string = result.stdout
        # Pretty print the XML
        try:
            root = ET.fromstring(xml_string)
            pretty_xml = ET.tostring(root, encoding='unicode', method='xml')
            xml_output = '<?xml version="1.0" encoding="UTF-8"?>\n' + pretty_xml
            return xml_output
        except ET.ParseError as e:
            return f"XML parsing error: {e}\nRaw XML output:\n{xml_string}"
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Tshark error: {e}"
        if e.stderr:
            error_msg += f"\nTshark stderr: {e.stderr}"
        raise Exception(error_msg)
    except ValueError as e:
        raise e
    except Exception as e:
        raise Exception(f"An error occurred: {e}")
    finally:
        # Clean up temporary file
        if tmp_file_path and os.path.exists(tmp_file_path):
            try:
                os.unlink(tmp_file_path)
            except:
                pass

@app.route('/parse_packet', methods=['GET'])
def parse_packet_endpoint():
    """
    HTTP endpoint to parse a hex packet and return XML output
    Expects 'packet' parameter in the query string
    Example: /parse_packet?packet=1a2b3c4d
    """
    try:
        # Get packet parameter from query string
        hex_packet = request.args.get('packet')
        if not hex_packet:
            return jsonify({
                'error': 'Invalid request: "packet" parameter is required in query string'
            }), 400
        
        # Parse the packet and get XML output
        xml_output = parse_packet_to_xml(hex_packet)
        
        # Return XML response
        return Response(
            xml_output,
            mimetype='application/xml',
            status=200
        )
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/")
def index():
    return render_template('index.html')

# Example usage when running locally
if __name__ == "__main__":
    # Example Ethernet packet with IP and TCP (simple SYN packet)
    sample_hex_packet = """
    ffffffffffff000c295e4d0808004500
    00340000f000400601bb0a000001c0a8
    000106ba0050e609e8f300000000a002
    7210fe2c0000020405b4010303080101
    0402
    """
    
    # For testing without HTTP, uncomment the following:
    # print("Parsing sample packet to XML...")
    # result = parse_packet_to_xml(sample_hex_packet)
    # print(result)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True,)