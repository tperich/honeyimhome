from args import build_parser

from rich import print
from scapy.layers.dot11 import Dot11, Dot11ProbeReq
from scapy.sendrecv import sniff


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
    args = build_parser().parse_args()

    if args.command == "scan":
        if args.database:
            # Load targets from DB
            # MACs are used for scanning, and names/clients for displaying to user
            pass

        try:
            scan_clients(
                interface=args.iface,
                target_mac=args.mac,
                target_ssid=args.ssid,
            )
        except KeyboardInterrupt:
            exit(0)

# Stubs


def _database_stub():
    # conn = sqlite3.connect("clients.db")
    # c = conn.cursor()

    # c.execute(
    #     """CREATE TABLE IF NOT EXISTS clients (
    #     mac text PRIMARY KEY,
    #     ssid text NOT NULL
    # )"""
    # )
    # conn.commit()

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

    # c.close()
    # conn.close()
