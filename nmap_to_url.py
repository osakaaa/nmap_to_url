import sys
import xml.etree.ElementTree as ET

def parse_nmap(_content):
    root = ET.fromstring(_content)
    result = []
    HTTP_SERVICES = ["http", "https", "ssl", "http-proxy"]
    for host in root.iter('host'):
        hosts2 = {}
        xmlstr = ET.tostring(host, encoding='utf8', method='xml')
        address = host.find('address').attrib['addr']
        try:
            host_name = host.find('hostnames').find('hostname').attrib['name']
        except Exception:
            host_name = address
        hosts2["hostName"] = host_name
        hosts2["address"] = address
        hosts2["ports"] = []
        try:
            for port in host.find('ports').iter('port'):
                product = ""
                tunnel = ""
                service = ""
                if port.find('service').attrib['name'] in HTTP_SERVICES or "http" in port.find('service').attrib['name']:
                    service = "http"
                else:
                    service = port.find('service').attrib['name']
                if "tunnel" in port.find('service').attrib:
                    tunnel = port.find('service').attrib['tunnel']
                if "product" in port.find('service').attrib:
                    product = port.find('service').attrib['product']
                if "version" in port.find('service').attrib:
                    product += " " + port.find('service').attrib['version']

                extra = ""
                if "extrainfo" in port.find('service').attrib:
                    extra += port.find('service').attrib['extrainfo'] + "\n"

                hosts2["ports"].append({
                    "portState": port.find('state').attrib['state'],
                    "portNumber": port.attrib['portid'],
                    "portTunnel": tunnel,
                    "portService": service,
                    "portProduct": product,
                    "portExtra": extra})
        except Exception as e:
            print(e)
            pass
        if hosts2:
            result.append(hosts2)

    return result


if __name__ == "__main__":
    scan = ""
    result_type = "hostName"
    with open(sys.argv[1],'r') as f:
        scan = f.read()
    if len(sys.argv) >= 2 and sys.argv[2] == "ip":
        result_type = "address"
    result = parse_nmap(scan)
    for host in result:
        for port in host["ports"]:
            proto = port["portService"]
            if port["portTunnel"]:
                proto = proto + "s"
            url = proto + "://" + host[result_type] + ":" + port["portNumber"]
            print(url)
