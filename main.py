import sqlite3
import argparse

from rich import print
from scapy.layers.dot11 import Dot11, Dot11ProbeReq
from scapy.sendrecv import sniff

# define arguments
parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

# `scan` command
scan_parser = subparsers.add_parser(
    "scan", help="Scan for wireless clients, if no target supplied, pull from DB"
)
scan_parser.add_argument(
    "-i", "--iface", help="Name of the wireless interface to use", required=True
)
scan_parser_by = scan_parser.add_mutually_exclusive_group(required=True)
scan_parser_by.add_argument(
    "-m", "--mac", help="Notify when this MAC address is detected"
)
scan_parser_by.add_argument("-s", "--ssid", help="Notify when this SSID is detected")
scan_parser_by.add_argument("-d", "--database", help="Database to get targets from")

# `add` command
add_parser = subparsers.add_parser("add", help="Add a known client to database")
add_parser.add_argument(
    "-d", "--database", help="List clients in the database", required=True
)
add_parser.add_argument("-l", "--list", help="List clients in the database")


def database():
    conn = sqlite3.connect("clients.db")
    c = conn.cursor()

    c.execute(
        """CREATE TABLE IF NOT EXISTS clients (
        mac text PRIMARY KEY,
        ssid text NOT NULL
    )"""
    )
    conn.commit()

    # c.execute("SELECT * FROM clients WHERE mac = ?", (src,))
    # client = c.fetchone()

    # if client is None:
    #     # Add new client to DB
    #     # print("[bold green][+][/bold green] [green]{} [{}]".format(ssid, src))
    #     c.execute("INSERT INTO clients (mac, ssid) VALUES (?, ?)", (src, ssid))
    #     conn.commit()
    # else:
    #     # Client already exists in DB
    #     # print("[bold gray][R][/bold gray] [gray]{} [{}]".format(ssid, src))
    #     pass

    c.close()
    conn.close()


def scan_clients(interface, target_mac, target_ssid):
    target = target_mac or target_ssid
    print(
        f"[$] Running on [bold]{interface}[/bold], looking for [bold bright_green]{target}"
    )

    def process_packet(packet):
        if not packet.haslayer(Dot11ProbeReq) or packet[Dot11].type != 0:
            return
        src = packet[Dot11].addr2
        ssid = packet[Dot11ProbeReq].info.decode("utf-8")

        # Notify when target appears
        if target_mac and src.lower() == target_mac.lower():
            print(f"[:rocket:] {target_mac} is here!")

        if target_ssid and ssid.lower() == target_ssid.lower():
            print(f"[:rocket:] {ssid} is here!")

    sniff(iface=interface, prn=process_packet)


if __name__ == "__main__":
    args = parser.parse_args()
    print(args)

    if args.command == "scan":
        if args.database:
            print(args.database)

            exit()

        try:
            scan_clients(
                interface=args.iface,
                target_mac=args.mac,
                target_ssid=args.ssid,
            )
        except KeyboardInterrupt:
            exit(0)

    # if args.command == "add":
    #     print(f"Adding client: {args.ssid}, {args.mac}")
