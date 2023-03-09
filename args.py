import argparse


def build_parser():
    # define arguments
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        title="subcommands", dest="command", required=True
    )

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
    scan_parser_by.add_argument(
        "-s", "--ssid", help="Notify when this SSID is detected"
    )
    scan_parser_by.add_argument("-d", "--database", help="Database to get targets from")

    # # `add` command
    # add_parser = subparsers.add_parser("add", help="Add a known client to database")
    # add_parser.add_argument(
    #     "-d", "--database", help="List clients in the database", required=True
    # )
    # add_parser.add_argument("-l", "--list", help="List clients in the database")

    return parser
