# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import dpkt
from tabulate import tabulate

def ip_resolve(eth):
    ip = eth.hex()
    realip = ""
    for i in range(0, len(ip), 2):
        realip += str(int(ip[i:i + 2], 16)) + "."
    return realip[0:-1]


def add_dict(dict, tuples, tupleh):
    key = False
    for i in dict.keys():
        if (i[0] == tuples[0] or i[0] == tuples[2]) and (i[1] == tuples[3] or i[1] == tuples[1]) and (
                i[2] == tuples[0] or i[2] == tuples[2]) and (i[3] == tuples[3] or i[3] == tuples[1]):
            if i[-1] != 17 and i[-1] != "20":
                dict[i].append(tuples)
                key = True
            elif i[-1] == 17:
                tuples.append("20")
                dict[i].append(tuples)
                key = True
    if not key:
        if tuples[-1] == 2:
            dict[tuple(tupleh)] = [tuples]



def pcapAna():
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    count = 0
    dictionary = {}
    for ts, buf in pcap:
        if count < 1000:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_layer = eth.data
            tcp_layer = ip_layer.data
            ip_s = ip_resolve(ip_layer.src)
            ip_d = ip_resolve(ip_layer.dst)
            sport = tcp_layer.sport
            dport = tcp_layer.dport
            flag = tcp_layer.flags
            seq = tcp_layer.seq
            ack = tcp_layer.ack
            win = tcp_layer.win
            tupleh = [sport, ip_s, dport, ip_d]
            tuples = [sport, ip_s, dport, ip_d, seq, ack, win, flag]
            add_dict(dictionary, tuples,tupleh)
        count += 1
    for i in dictionary:
        print(i)
        for j in dictionary[i]:
            print(j)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    pcapAna()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
