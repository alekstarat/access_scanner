import re
import subprocess

def parse_nmap(text: str):
    result = {}

    ip_match = re.search(r"Nmap scan report for ([\d\.]+)", text)
    latency_match = re.search(r"Host is up \(([\d\.]+s) latency\)", text)

    if ip_match:
        result["ip"] = ip_match.group(1)
    if latency_match:
        result["latency"] = latency_match.group(1)

    port_match = re.search(r"(\d+/tcp)\s+(\w+)\s+([\w\-]+)", text)
    if port_match:
        result["port"] = port_match.group(1)
        result["state"] = port_match.group(2)
        result["service"] = port_match.group(3)

    encryption = {}
    security_layer = []
    for line in text.split("\n"):
        if "CredSSP" in line or "RDSTLS" in line or "SSL" in line:
            key, val = line.replace("|", "").strip().split(":")
            security_layer.append({key.strip(): val.strip()})
        if "RDP Protocol Version" in line:
            val = line.split(":", 1)[1].strip()
            encryption["rdp_protocol_version"] = val

    if security_layer:
        encryption["security_layer"] = security_layer
    if encryption:
        result["rdp_enum_encryption"] = encryption

    ntlm_info = {}
    ntlm_matches = re.findall(r"\|\s+(\w+):\s+([^\s]+)", text)
    for key, val in ntlm_matches:
        if key != "Security":
            ntlm_info[key.lower()] = val

    if ntlm_info:
        result["rdp_ntlm_info"] = ntlm_info

    return result

if __name__ == "__main__":
    result = subprocess.run(['/home/arch/Desktop/git/access_scanner/chains/rdp/rdp.sh', '8.153.71.147'], text=True, capture_output=True, check=True)

    print(parse_nmap(result.stdout))