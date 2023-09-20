import psutil
import socket
import time
import os
import sys
import random
import csv
from statistics import mean
from collections import Counter

traffic_types = ['video', 'browsing', 'download', 'upload']
probabilities = [0.825, 0.128, 0.035, 0.012]

ue_cmd = "sudo /home/core/UERANSIM/build/nr-ue -c  /home/core/UERANSIM/config/open5gs-ue" #change path to reflect your environment
gnb_cmd = "sudo /home/core/UERANSIM/build/nr-gnb -c  /home/core/UERANSIM/config/open5gs-gnb" #change path to reflect your environment

def choose_line(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
    
    random_line = random.choice(lines)
    return random_line

def interface_created(interfaces):
  created = True
  if type(interfaces) is not list:
    print("List of interfaces is needed")
    return
  else:
     for interface in interfaces:
       interface_addrs = psutil.net_if_addrs().get(interface) or []
       created = socket.AF_INET in [snicaddr.family for snicaddr in interface_addrs]
       if created is False:
         return created
  return created
  
def choose_option(options, probabilities):
    if len(options) != len(probabilities):
        raise ValueError("Number of options must be equal to the number of probabilities")
    
    selected_option = random.choices(options, probabilities)[0]
    return selected_option

def get_uessimtun_ips():
    uessimtun_ips = []

    # Get a list of network interfaces
    interfaces = psutil.net_if_addrs()

    for interface_name, interface_addresses in interfaces.items():
        if "uesimtun" in interface_name and interface_name != "uesimtun0":
            for addr in interface_addresses:
                if addr.family == socket.AF_INET:  # IPv4 address
                    uessimtun_ips.append(addr.address)

    return uessimtun_ips
  
def start_setup(number_of_gnbs, number_of_ues):
  
  print("Starting {} gNBs with {} UEs connected to each gNB".format(number_of_gnbs, number_of_ues))

  default_unsuccess = 0
  i = 0
  
  # Try to start as many gNBs as specified
  while i < number_of_gnbs:
    i+=1
    os.system("sudo pkill -9 -f open5gs-gnb{}".format(i))
    unsuccess = 0
    cmd = gnb_cmd + "{}.yaml > /dev/null &".format(i)
    os.system(cmd)
    time.sleep(3)
    
    # start standard UE in DNN: operator-network. If resetting this UE fails 5 times stop the script
    while not interface_created(["uesimtun0"]):
      os.system("sudo pkill -9 -f open5gs-ue")
      cmd = ue_cmd + ".yaml > /dev/null &"
      os.system(cmd)
      time.sleep(2)
      default_unsuccess += 1
      if default_unsuccess > 5:
        print("Unable to start standard UE")
        return
    
    interfaces = [f"uesimtun{i}" for i in range((i-1)*number_of_ues+1, (i-1)*number_of_ues+number_of_ues+1)] #create a list of uesimtun interfaces that reflect emulated UE. Number of UEs (length of list) is equal to command line argument that specifies how many UEs will be connected to each gNB
    # try to start specified number of UEs. After 5 unsuccessfull attempts to start specified number of UEs, restart gNB to which those UEs are connecting and then start UEs again (standard UE will be started again if problems were for gNB 1)
    while not interface_created(interfaces):
      os.system("sudo pkill -9 -f open5gs-ue{}".format(i))
      cmd = ue_cmd + "{}.yaml -n {} > /dev/null &".format(i, number_of_ues)
      os.system(cmd)
      time.sleep(2)
      unsuccess += 1
      if unsuccess > 5:
        print("Having troubles with gNB{}".format(i))
        i -= 1
        break
    
  #print("All UEs started successfully")
  os.system("sudo ip route add 0.0.0.0/0 dev uesimtun1") #first non-standard UE used for DNS
  os.system("sudo ip route add 192.168.56.115/32 dev uesimtun0") #standard UE should be used to reach iPerf server, change to IP of iperf server in your environment
  
def generate_traffic(uessimtun_ips):
    
  #selected_options = []
  for ip in uessimtun_ips:
    selected = choose_option(traffic_types, probabilities) #choose types of generated traffic
    #selected_options.append(selected)
    if selected == "video":
      filename = '/home/core/movies.txt' #change path to reflect your environment
      link = choose_line(filename)
      os.system("watch -n 5 ./nr-binder {} ffmpeg -i '{}' -f null /dev/null > /dev/null 2>&1 &".format(ip, link))
    elif selected == "browsing":
      filename = '/home/core/websites.txt' #change path to reflect your environment
      link = choose_line(filename) 
      os.system("watch -n 5 ./nr-binder {} wget -O /dev/null -o /dev/null '{}'> /dev/null &".format(ip, link))
    elif selected == "download":
      filename = '/home/core/files.txt' #change path to reflect your environment
      link = choose_line(filename)
      os.system("watch -n 5 ./nr-binder {} wget -O /dev/null -o /dev/null '{}' > /dev/null &".format(ip, link))    
    elif selected == "upload":
      os.system("watch -n 5 ./nr-binder {} python3 /home/core/ftp.py > /dev/null &".format(ip)) #change path to reflect your environment
  
  #check types of traffic that will be generated
  
  #element_count = Counter(selected_options)
  #output = ", ".join(f"{element}: {count} UEs" for element, count in element_count.items())
  #print(output)
  
  os.system("sudo rm iperf.log")
  
  #UDP
  os.system("timeout 35 iperf3 -R -c 192.168.56.115 -t 30 -u -b 50M --logfile iperf.log")
  #TCP
  #os.system("timeout 35 iperf3 -c 192.168.56.115 -t 30 --logfile iperf.log")
  
  #reading iPerf results from iperf.log generated above, code below reflects structure of this file saved on iPerf client in UDP, reversed mode 
  #change read lines and list indexes for TCP
  try:
    with open("iperf.log", "r") as file:
      lines = file.readlines()
      #sometimes there is an additional line in iperf.log and this needs to be checked
      if lines[-4].split()[0] == "[SUM]":
        jitter_lines = lines[4:-7]
        summary_line = lines[-3]
      else:
        jitter_lines = lines[4:-6]
        summary_line = lines[-3]
        
      jitters = []
      for line in jitter_lines:
        jitters.append(float(line.split()[8]))
      
      bitrate = summary_line.split()[6]
      
      if float(bitrate) == 0:
        print("-------------------------------------------------------------------------------------------------")
        print("ZERO BITRATE")
        print("-------------------------------------------------------------------------------------------------")
        bitrate = "PROBLEM"
        jitter = "PROBLEM"
        packets_lost = "PROBLEM"
      else:
        bitrate = float(bitrate)
        jitter = round(mean(jitters), 2)     
        packets_lost = summary_line.split()[11].replace("(", "").replace(")", "")

  except:
    print("-------------------------------------------------------------------------------------------------")
    print("PROBLEMS WITH IPERF")
    print("-------------------------------------------------------------------------------------------------")
    bitrate = "PROBLEM"
    jitter = "PROBLEM"
    packets_lost = "PROBLEM"
  
  return [bitrate, jitter, packets_lost]
       

def write_results(filename, data, gnb_count):
      
  row_number_to_update = gnb_count
  bitrate = data[0]
  jitter = data[1]
  packets_lost = data[2]
  
  existing_data = []
  
  with open(filename, mode='r') as csv_file:
    csv_reader = csv.reader(csv_file)
    for row in csv_reader:
      existing_data.append(row)
  
  #it is assumed that .csv file which will contain result has first column filled with parameter and number of gNBs in given scenario, and that tests will be run for 1-8 gNBs. 
  #So, in first row there is "Bitrate, 1 gnB", in second row there is "Bitrate, 2 gNB", in 9th row there is "Jitter, 1 gNB" etc.
  #Comment line with writing jitter and packets_lost in case of TCP
  if row_number_to_update + 16 < len(existing_data):
    existing_data[row_number_to_update].extend([bitrate])
    existing_data[row_number_to_update+8].extend([jitter])
    existing_data[row_number_to_update+16].extend([packets_lost])
      
    with open(filename, mode='w', newline='') as csv_file:
      csv_writer = csv.writer(csv_file)
      csv_writer.writerows(existing_data)

  else:
      print("Row number is out of range.")        


def main():
  args = sys.argv[1:]
  if len(args) == 4 and args[0] == '-gnbs' and args[2] == '-ues':
    gnb_count = int(args[1]) #number of gNBs to be started
    ue_count = int(args[3]) #number of UEs that will connect to each gNB and generate traffic
    
    #make sure all processes related to traffic generation and UERANSIM emulation are killed
    os.system("sudo pkill -9 -f iperf")
    os.system("sudo pkill -9 -f nr-binder")
    os.system("sudo pkill -9 -f ffmpeg")
    os.system("sudo pkill -9 -f wget")
    os.system("sudo pkill -9 -f /home/core/ftp.py")
    os.system("sudo pkill -9 -f UERANSIM")
    
    os.chdir("/home/core/UERANSIM/build") #change path to reflect your environment, directory has to contain nr-binder as it has to be used from the very directory that it is located in
    start_setup(gnb_count, ue_count)
    
    uessimtun_ips = get_uessimtun_ips()
    #check whether the expected number of UEs has been successfully launched
    if len(uessimtun_ips) != gnb_count*ue_count:
      print("Not every UE connected")
      return
    
    results = generate_traffic(uessimtun_ips)
    write_results('/home/core/results_udp_one_flow_mirroring.csv', results, gnb_count) #change path to reflect your environment
    
    os.system("sudo pkill -9 -f iperf")
    os.system("sudo pkill -9 -f nr-binder")
    os.system("sudo pkill -9 -f ffmpeg")
    os.system("sudo pkill -9 -f wget")
    os.system("sudo pkill -9 -f /home/core/ftp.py")
    os.system("sudo pkill -9 -f UERANSIM")
    
  else:
    print("Wrong command line arguments. Python script has to be run like this: 'python setup.py -gnbs <number-of-gnbs> -ues <number-of-ues>'")
    return

if __name__ == '__main__':
  main()
  