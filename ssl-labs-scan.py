from requests import get, head
import json
import time
import csv
import sys
import argparse

__author__ = 'K. Coddington'
# https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md


def setargs():
    description = 'This script will scan one or several URLs using the Qualys SSL Labs Scan API. Single scan results ' \
                  'will be displayed in stdout, while scanning from a list will output to a CSV.'
    usage = "\n\nssl-labs-scan.py [-ss URL] [-ms URL_LIST -o OUTPUT_CSV]"
    parser = argparse.ArgumentParser(description=description, usage=usage)

    parser.add_argument('-ss', '--single-site',
                        dest='url',
                        help='Scan a single URL')
    parser.add_argument('-ms', '--multi-site',
                        dest='url_list',
                        help='Scan multiple URLs from newline-delimited text file')
    parser.add_argument('-o', '--output',
                        dest='output_csv',
                        default='output.csv',
                        help='<<Requires -ms option to be set>> Sets file that will receive output results. '
                             'Default = output.csv')

    return parser.parse_args()


def verify_api():
    api_info_url = 'https://api.ssllabs.com/api/v2/info'
    response = json.loads(get(api_info_url).text)
    return response['engineVersion']


def ssllab_scan(url):
    print("\nScanning %s..." % url)
    scan_url = 'https://api.ssllabs.com/api/v2/analyze?host=%s&all=on&ignoreMismatch=on&fromCache=on&maxAge=24' % url
    response = json.loads(get(scan_url).text)
    if response['status'] != 'READY' and response['status'] != 'ERROR':
        print("   Cached results not found. Running new scan. This could take up to 90 seconds to complete.")
    while response['status'] != 'READY' and response['status'] != 'ERROR':
        time.sleep(4)
        response = json.loads(get(scan_url).text)  # stated again to refresh response variable
    if response['status'] == 'READY' and response['endpoints'][0]['statusMessage'] != 'Ready':
        print("   %s" % response['endpoints'][0]['statusMessage'])
        return response
    return response


def get_protocol(proto, parsed_json):
    proto_dict = {'ssl2': 512, 'ssl3': 768, 'tls10': 769, 'tls11': 770, 'tls12': 771}
    proto_list = parsed_json['endpoints'][0]['details']['protocols']
    result = any(p['id'] == proto_dict[proto] for p in proto_list)
    return result


def get_qualys_grades(parsed_json_text):
    p = parsed_json_text
    grade = p['endpoints'][0]['grade']
    ti_grade = p['endpoints'][0]['gradeTrustIgnored']
    if grade != 'T':
        return grade
    else:
        return "%s(%s)" % (grade, ti_grade)


def get_fallback(parsed_json_text):
    return parsed_json_text['endpoints'][0]['details']['fallbackScsv']


def get_forward_secrecy(parsed_json_text):
    p = parsed_json_text['endpoints'][0]['details']['forwardSecrecy']
    if p < 1:
        return 'False'
    else:
        return 'True'


def get_poodle_ssl(parsed_json_text):
    return parsed_json_text['endpoints'][0]['details']['poodle']


def get_poodle_tls(parsed_json_text):
    p = parsed_json_text['endpoints'][0]['details']['poodleTls']
    if p == 2:
        return 'True'
    elif p == 1:
        return 'False'
    elif p == -1:
        return 'Test failed'
    elif p == -2:
        return 'TLS not supported'
    elif p == -3:
        return 'Inconclusive (Timeout)'


def get_freak(parsed_json_text):
    return parsed_json_text['endpoints'][0]['details']['freak']


def get_logjam(parsed_json_text):
    return parsed_json_text['endpoints'][0]['details']['logjam']


def get_crime(parsed_json_text):
    p = parsed_json_text['endpoints'][0]['details']['compressionMethods']
    if p == 0:
        return 'False'
    else:
        return 'True'


def get_heartbleed(parsed_json_text):
    return parsed_json_text['endpoints'][0]['details']['heartbleed']


def single_site_output(parsed_json_text):
    if not parsed_json_text:
        main()
    p = parsed_json_text
    print("\n--------------------------------------------------------------")
    print("  Results for " + p['host'] + ":\n")
    print("  IP Address: %s" % p['endpoints'][0]['ipAddress'])
    print("  Grade: %s\n" % get_qualys_grades(p))
    print("  SSLv2:   %s" % get_protocol('ssl2', p))
    print("  SSLv3:   %s" % get_protocol('ssl3', p))
    print("  TLSv1.0: %s" % get_protocol('tls10', p))
    print("  TLSv1.1: %s" % get_protocol('tls11', p))
    print("  TLSv1.2: %s\n" % get_protocol('tls12', p))
    print("  TLS Fallback SCSV implemented:       %s" % get_fallback(p))
    print("  Uses Forward Secrecy:                %s" % get_forward_secrecy(p))
    print("  Vulnerable to POODLE (SSLv3) attack: %s" % get_poodle_ssl(p))
    print("  Vulnerable to POODLE (TLS) attack:   %s" % get_poodle_tls(p))
    print("  Vulnerable to FREAK attack:          %s" % get_freak(p))
    print("  Vulnerable to Logjam attack:         %s" % get_logjam(p))
    print("  Vulnerable to CRIME attack:          %s" % get_crime(p))
    print("  Vulnerable to Heartbleed attack:     %s" % get_heartbleed(p))
    print("--------------------------------------------------------------\n")


def get_url_list(listfile):
    url_list = []
    with open(listfile, 'r') as inf:
        a = map(str.strip, inf.readlines())
        for line in a:
            url_list.append(line)
    return url_list


def scan_kickoff(url_list):
    counter = 0
    print("\n------------------------------------------------------------")
    for url in url_list:
        scan_url = 'https://api.ssllabs.com/api/v2/analyze?host=%s&all=on&ignoreMismatch=on&startNew=on' % url
        counter += 1
        if counter % 20 == 0:
            print(" Concurrent scan limit exceeded. Waiting for cooldown...")
            time.sleep(90)
        time.sleep(1)
        print(" Kicking off scan for %s..." % url)
        head(scan_url)
    time.sleep(90)
    print(" All scans complete.")
    print("------------------------------------------------------------\n\n")


def get_cached_results(url_list):
    cached_list = []
    for url in url_list:
        time.sleep(1)
        try:
            results = 'https://api.ssllabs.com/api/v2/analyze?host=%s&all=done&fromCache=on&maxAge=24' % url
            response = json.loads(get(results).text)
            cached_list.append(response)
        except TypeError:
            print("%s could not be successfully scanned and will not be included in output file.")
    return cached_list


def csv_output(inlist, outfile):
    url_list = get_url_list(inlist)  # parses list of URLs for scanning
    scan_kickoff(url_list)
    l = get_cached_results(url_list)
    print("------------------------------------------------------------")
    print(" Writing results to %s...\n" % outfile)
    with open(outfile, 'wb+') as outf:
        b = csv.writer(outf, dialect='excel', lineterminator='\n')
        b.writerow(['Site', 'IP Address', 'Qualys Grade', 'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2',
                    'TLS Fallback SCSV', 'Forward Secrecy', 'POODLE (SSLv3)', 'POODLE (TLS)', 'FREAK', 'Logjam',
                    'CRIME', 'Heartbleed'])  # insert header row
        for p in l:
            if p['status'] == 'READY' and p['endpoints'][0]['statusMessage'] != 'Ready':
                print("   %s for %s" % (p['endpoints'][0]['statusMessage'], p['host']))
                print("   %s not added to csv.\n" % p['host'])
                continue
            b.writerow([p['host'], p['endpoints'][0]['ipAddress'], get_qualys_grades(p), get_protocol('ssl2', p),
                        get_protocol('ssl3', p), get_protocol('tls10', p), get_protocol('tls11', p),
                        get_protocol('tls12', p), get_fallback(p), get_forward_secrecy(p), get_poodle_ssl(p),
                        get_poodle_tls(p), get_freak(p), get_logjam(p), get_crime(p), get_heartbleed(p)])
    print(" Writing to %s complete." % outfile)
    print("------------------------------------------------------------\n\n")


def main():
    args = setargs()
    if not verify_api():
        print("SSL Labs API is not reachable at this time. Exiting.")
        sys.exit(0)

    if args.url:
        single_site_output(ssllab_scan(args.url))
        sys.exit(0)

    if args.url_list and args.output_csv:
        csv_output(args.url_list, args.output_csv)
        sys.exit(0)

    if args.url_list and not args.output_csv:
        print("Output file not set. Please use -h for more information.")
        sys.exit(0)

if __name__ == '__main__':
    main()
