from xml.etree import ElementTree as ET
import urllib.parse
import base64
import csv

log_path = "burp_demo.log"
output_csv_log = "http_sql_log.csv"
class_flag = "1"

class LogParse:
    def __init__(self):
        pass
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
        decoded_resp = base64.b64decode(raw_resp.encode())  # Encode to bytes before decoding
        result[raw_req] = decoded_resp
    
    
    def parseRawHTTPReq(rawreq):
        try:
            raw = rawreq.decode('utf8')
        except Exception as e:
            raw = rawreq
        headers = {}
        sp = raw.split('\r\n\r\n', 1)  # Change this to '\n'
        if sp[1] != "":
            head = sp[0]
            body = sp[1]
        else:
            head = sp[0]
            body = ""
        c1 = head.split('\n', head.count('\n'))
        method = c1[0].split(' ', 2)[0]
        path = c1[0].split(' ', 2)[1]
        for i in range(1, head.count('\n') + 1):
            slice1 = c1[i].split(': ', 1)
            if slice1[0] != "":
                try:
                    headers[slice1[0]] = slice1[1]
                except:
                    pass
        return headers, method, body, path

    


badwords = ['sleep','drop','select','waitfor','delay','system','union','order by','group by']
def ExtractFeatures(method,path_enc,body_enc,headers):
    badwords_count = 0
    path = urllib.unquote_plus(path_enc)
    body = urllib.unquote(body_enc)
    single_q = path.count("'")+body.count("'")
    double_q = path_count("\"") + body.count("\"")
    dashes = path.count("--")+ body.count("--")
    braces = path.count("(") + body.count("(")
    spaces = path.count(" ")+ body.count(" ")
    for word in badwords:
        badwords_count += path.count(word) + body.count(word)
    for header in headers:
        badwords_count += headers[header].count(word) + headers[header].count(word)
    
    return [method,path_enc.encode('utf-8').strip(),body_enc.encode('utf-8').strip(),single_q,double_q,dashes,braces,spaces]
    raw_input('>>>')


#Open the log file

f = open(output_csv_log,"w")
c = csv.writer(f)
c.writerow(["method", "body", "path", "single_q","double_q","dashes","braces","spaces","badwords","class"])
f.close()
lp = LogParse()
result = lp.parse_log(log_path)
f = open(output_csv_log, "ab")
c = csv.writer(f)
for item in result:
    decoded_response = base64.b64decode(item)
    raaw = decoded_response.decode()  # The value is already bytes
    headers, method, body, path = lp.parseRawHTTPReq(raaw)
    result = ExtractFeatures(method,path,body,headers)
    c.writerow(result)
f.close()
