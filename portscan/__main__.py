import argparse


from portscan.scanner import Scanner


if __name__ == '__main__':
    arguments_parser = argparse.ArgumentParser()
    arguments_parser.add_argument('ip', default='127.0.0.1', type=str)
    arguments_parser.add_argument('-u', action='store_true', dest='udp')
    arguments_parser.add_argument('-t', action='store_true', dest='tcp')
    arguments_parser.add_argument('-p', '--ports', nargs='+', dest='ports')
    args = arguments_parser.parse_args()
    if len(args.ports) != 2:
        print('Введите диапозон портов')
        exit(0)
    scanner = Scanner(args.ip, args.udp, args.tcp, args.ports)
    scanner.run()
