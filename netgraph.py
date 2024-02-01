import argparse

from netwulf import visualize
import networkx as nx
from scapy.all import PcapReader
from tqdm import tqdm
from humanize import naturalsize

parser = argparse.ArgumentParser(
        prog='netgraph.py',
        description='Traffic based network graphing tool',
)

parser.add_argument('-p', '--pcap', required=True, type=str, help='Pcap/cap file to read traffic from')
parser.add_argument('-i', '--ip', type=str, help='IP address to focus on. Ignores unrelated traffic')

args = parser.parse_args()

PCAP_FILE = args.pcap
FOCUS_IP = args.ip

G = nx.Graph()
pcap = open(PCAP_FILE, 'rb')
CAPTURE = PcapReader(pcap)

for pkt in tqdm(CAPTURE):
    if 'Ether' not in pkt or pkt.type != 2048:
        continue

    src = pkt['IP'].src
    dst = pkt['IP'].dst
    size = pkt['IP'].len

    if FOCUS_IP and not (src == FOCUS_IP or dst == FOCUS_IP):
        continue

    if not G.has_node(src):
        G.add_node(src)

    if not G.has_node(dst):
        G.add_node(dst)

    if not G.has_edge(src, dst):
        G.add_edge(src, dst, weight=0)

    G.edges[src, dst]['weight'] += size
    G.edges[src, dst]['label'] = G.edges[src, dst]['weight']

visualize(G, config={'freeze_nodes': True, 'link_width': 5})
