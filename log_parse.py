from xml.etree import ElementTree as ET
import urllib.parse
import base64


log_path = "burp_demo.log"

def parse_log(log_path):
    '''
    This function accepts a burp log file path.
    and returns a dict. of request and response
    result = {'GET /page.php...': '200 OK HTTP / 1.1....', ...}
    '''
    result = {}
    try:
        with open(log_path):
            pass
    except IOError:
        print("[+] Error!!!", log_path, "doesn't exist..")
        exit()
    try:
        tree = ET.parse(log_path)
    except Exception as e:
        print('[+] Oops..! Please make sure binary data is not present in Log, like raw image dump, flash(.swf files) dump etc')
        exit()
    root = tree.getroot()
    for reqs in root.findall('item'):
        raw_req = reqs.find('request').text
        raw_req = urllib.parse.unquote(raw_req)
        raw_resp = reqs.find('response').text
        result[raw_req] = raw_resp
    return result

result = parse_log(log_path)
for items in result:
    print(items)
print(decoded_response.decode())



for item in result:
    decoded_response = result[item]  # The value is already bytes