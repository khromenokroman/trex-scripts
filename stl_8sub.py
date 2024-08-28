#!/usr/bin/python3
import pprint
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import sys

sys.path.append('/home/user/trex/scripts/automation/trex_control_plane/interactive')

from trex_stl_lib.api import *
import traceback
import warnings
import json
import argparse
from bin import statistics_show


def get_settings():
    parser = argparse.ArgumentParser(
        prog='python3 trex_clint.py',
        description='Using TREX generate two streams via two ports',
        epilog='Ymishustin 2024',
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-s',
                        '--speed',
                        type=str,
                        help='Указать целевую TX скорость одного порта в формате 1, 1G, 1M, 100p. Значение без литеры - гигабит. Литера p = кол-во пакетов в секунду')

    parser.add_argument('-t',
                        '--time',
                        type=float,
                        required=True,
                        help='Указать время подачи трафика в секундах.')

    parser.add_argument('-p',
                        '--packet_size',
                        type=int,
                        default=1500,
                        help='Указать размер пакета в байтах (только для автоматической генерации трафика)')

    parser.add_argument('--capture',
                        type=str,
                        help='Захват трафика')

    args = parser.parse_args()

    test_settings = {
        "speed": args.speed,  # Нагрузка
        "duration": args.time,  # Длительность теста в секундах
        "packet_size": args.packet_size,  # Размер пакета
        "capture": args.capture,
    }

    return test_settings


class TrexClient:
    def __init__(self, server, sync_port, capture=None):
        self.server = server
        self.sync_port = sync_port
        self.client = None
        self.capture = capture
        self.sniffer = None

    def connecting(self):
        # self.client = STLClient(server=self.server, sync_port=self.sync_port)
        self.client = STLClient(server=self.server)
        self.client.connect()

    def clear_stats(self):
        self.client.clear_stats(ports=[0, 1])

    def reset_ports(self):
        self.client.reset(ports=[0, 1])

    def start_traffic(self, duration):
        if self.capture:
            port = int(self.capture)
            self.client.set_service_mode(ports=port, enabled=True)
            self.sniffer = self.client.start_capture(rx_ports=port, limit=100000, mode='fixed')
        self.client.start(ports=[0, 1], duration=duration, force=True)
        # self.client.start(ports=[0], duration=duration, force=True)

    def wait_traffic(self):
        self.client.wait_on_traffic(ports=[0, 1])
        if self.capture:
            port = int(self.capture)
            fname = f'ipv4_random_result_port{port}'
            print(f'Saving pcap to ./PCAPS/{fname}.pcap', end='\r')
            self.client.stop_capture(self.sniffer['id'], f'./PCAPS/{fname}.pcap')
            self.client.set_service_mode(ports=port, enabled=False)

    def get_stats(self):
        return self.client.get_stats()

    def add_stream_a(self, stream):
        self.client.add_streams(stream, ports=0)

    def add_stream_b(self, stream):
        self.client.add_streams(stream, ports=1)

    def disconnect(self):
        self.client.disconnect()


def main():
    test_settings = get_settings()

    speed = test_settings['speed'].upper()
    duration = test_settings['duration']
    packet_size = test_settings['packet_size']
    streams_count = 1
    capture = test_settings['capture']
    pps = 0
    total_speed = 0

    # Подключение к серверу trex
    trex_client = TrexClient('127.0.0.1', None, capture)
    trex_client.connecting()

    # Перевод скорости
    if 'M' in str(speed)[-1]:
        try:
            speed = speed.replace('M', '')
            speed = int(speed)
            total_speed = speed * 1000000
        except ValueError:
            trex_client.disconnect()
            print(f'Error!\n\tWrong format of speed: {speed} is not 1, 10, 10M, 1000M, 10G, 100G, 100P')
            return False
    elif 'G' in str(speed)[-1]:
        try:
            speed = speed.replace('G', '')
            speed = int(speed)
            total_speed = speed * 1000000000
        except ValueError:
            trex_client.disconnect()
            print(f'Error!\n\tWrong format of speed: {speed} is not 1, 10, 10M, 1000M, 10G, 100G, 100P')
            return False
    elif 'P' in str(speed)[-1]:
        try:
            speed = speed.replace('P', '')
            pps = int(speed) - 1
            speed = int(speed) * 1024
            if packet_size:
                total_speed = pps * packet_size
            else:
                total_speed = speed
            print(f'PPS FOUND! PPS: {pps}, speed: {total_speed}')
        except:
            trex_client.disconnect()
            print(f'Error!\n\tWrong format of speed: {speed} is not 1, 10, 10M, 1000M, 10G, 100G, 100P')
            return False
    else:
        try:
            speed = int(speed)
            total_speed = speed * 1000000000
        except ValueError:
            trex_client.disconnect()
            print(f'Error!\n\tWrong format of speed: {speed} is not 1, 10, 10M, 1000M, 10G, 100G, 100P')
            return False

    # Высчитать скорость для каждого стрима
    if pps:
        stream_speed = pps * packet_size / streams_count
    else:
        stream_speed = total_speed / streams_count

    # Инвентарь для стримов
    streams = {}

    # Индексация стримов
    stats_indexes = [i for i in range(1, (streams_count * 8) + 1)]

    # Наполнение пакета данными (размер пакета минус размер заголовка)
    def pad(base_pkt):
        number = '0123456789'
        alpha = 'abcdefghijklmnopqrstuvwxyz'
        payload = ''
        while len(payload) != (packet_size - len(base_pkt)):
            payload += random.choice(alpha)
            payload += random.choice(number)

        return payload

    print('Create streams ...', end='\r')
    # Формирование пакетов
    ip_range = [{'src': {'start': "10.1.0.0", 'end': "10.1.0.255"},
                 'dst': {'start': "10.2.0.0", 'end': "10.2.255.255"}},
                {'src': {'start': "10.3.0.0", 'end': "10.3.0.255"},
                 'dst': {'start': "10.4.0.0", 'end': "10.4.255.255"}},
                {'src': {'start': "10.5.0.0", 'end': "10.5.0.255"},
                 'dst': {'start': "10.6.0.0", 'end': "10.6.255.255"}},
                {'src': {'start': "10.7.0.0", 'end': "10.7.0.255"},
                 'dst': {'start': "10.8.0.0", 'end': "10.8.255.255"}}
                ]
    src1 = ip_range[0]['src']
    dst1 = ip_range[0]['dst']
    src2 = ip_range[1]['src']
    dst2 = ip_range[1]['dst']
    src3 = ip_range[2]['src']
    dst3 = ip_range[2]['dst']
    src4 = ip_range[3]['src']
    dst4 = ip_range[3]['dst']

    vm1 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=src1['start'],
                     max_value=src1['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=dst1['start'],
                     max_value=dst1['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=1,
                     max_value=3,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]
    vm2 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=dst1['start'],
                     max_value=dst1['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=src1['start'],
                     max_value=src1['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=1,
                     max_value=3,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]

    vm3 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=src2['start'],
                     max_value=src2['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=dst2['start'],
                     max_value=dst2['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=1,
                     max_value=3,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]
    vm4 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=dst2['start'],
                     max_value=dst2['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=src2['start'],
                     max_value=src2['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=1,
                     max_value=3,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]

    vm5 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=src3['start'],
                     max_value=src3['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=dst3['start'],
                     max_value=dst3['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=1,
                     max_value=3,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]
    vm6 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=dst3['start'],
                     max_value=dst3['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=src3['start'],
                     max_value=src3['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=1,
                     max_value=3,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]

    vm7 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=src4['start'],
                     max_value=src4['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=dst4['start'],
                     max_value=dst4['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=1,
                     max_value=3,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]
    vm8 = [
        # change ip.src
        STLVmFlowVar(name="src",
                     min_value=dst4['start'],
                     max_value=dst4['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

        # change ip.dst
        STLVmFlowVar(name="dst",
                     min_value=src4['start'],
                     max_value=src4['end'],
                     size=4, op="inc"),
        STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

        # change sport
        STLVmFlowVar(name="sport",
                     min_value=1,
                     max_value=3,
                     size=2, op="inc"),
        STLVmWrFlowVar(fv_name="sport", pkt_offset="UDP.sport"),

        # change dport
        STLVmFlowVar(name="dport",
                     min_value=10000,
                     max_value=10010,
                     size=2, op="dec"),
        STLVmWrFlowVar(fv_name="dport", pkt_offset="UDP.dport"),

        # fix ip.chksum
        STLVmFixIpv4(offset="IP"),
    ]

    for i in range(1, streams_count + 1):
        print(f'Channel {i}..', end='\r')
        base_pkt_dir_a = Ether() / IP() / UDP(chksum=0)  # создаем пакет A
        base_pkt_dir_b = Ether() / IP() / UDP(chksum=0)  # создаем пакет B
        base_pkt_dir_c = Ether() / IP() / UDP(chksum=0)  # создаем пакет C
        base_pkt_dir_d = Ether() / IP() / UDP(chksum=0)  # создаем пакет D
        base_pkt_dir_e = Ether() / IP() / UDP(chksum=0)  # создаем пакет E
        base_pkt_dir_f = Ether() / IP() / UDP(chksum=0)  # создаем пакет F
        base_pkt_dir_i = Ether() / IP() / UDP(chksum=0)  # создаем пакет I
        base_pkt_dir_g = Ether() / IP() / UDP(chksum=0)  # создаем пакет G

        streams[i] = {
            'name_a': f'A',
            'name_b': f'B',
            'name_c': f'C',
            'name_d': f'D',
            'name_e': f'E',
            'name_f': f'F',
            'name_i': f'I',
            'name_g': f'G',
            'a_bps_id': stats_indexes.pop(0),
            'b_bps_id': stats_indexes.pop(0),
            'c_bps_id': stats_indexes.pop(0),
            'd_bps_id': stats_indexes.pop(0),
            'e_bps_id': stats_indexes.pop(0),
            'f_bps_id': stats_indexes.pop(0),
            'i_bps_id': stats_indexes.pop(0),
            'g_bps_id': stats_indexes.pop(0),
            'a_to_b_pkt': base_pkt_dir_a,
            'b_to_a_pkt': base_pkt_dir_b,
            'c_to_d_pkt': base_pkt_dir_c,
            'd_to_c_pkt': base_pkt_dir_d,
            'e_to_f_pkt': base_pkt_dir_e,
            'f_to_e_pkt': base_pkt_dir_f,
            'i_to_g_pkt': base_pkt_dir_i,
            'g_to_i_pkt': base_pkt_dir_g,
            'stream_a': None,
            'stream_b': None,
            'stream_c': None,
            'stream_d': None,
            'stream_e': None,
            'stream_f': None,
            'stream_i': None,
            'stream_g': None,
            'a_stats': None,
            'b_stats': None,
            'c_stats': None,
            'd_stats': None,
            'e_stats': None,
            'f_stats': None,
            'i_stats': None,
            'g_stats': None,
        }

    for indx, data in streams.items():
        if pps:
            s1 = STLStream(packet=STLPktBuilder(pkt=data['a_to_b_pkt'] / pad(data['a_to_b_pkt']), vm=vm1),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['a_bps_id']))
            s2 = STLStream(packet=STLPktBuilder(pkt=data['b_to_a_pkt'] / pad(data['b_to_a_pkt']), vm=vm2),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['b_bps_id']))

            s3 = STLStream(packet=STLPktBuilder(pkt=data['c_to_d_pkt'] / pad(data['c_to_d_pkt']), vm=vm3),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['c_bps_id']))
            s4 = STLStream(packet=STLPktBuilder(pkt=data['d_to_c_pkt'] / pad(data['d_to_c_pkt']), vm=vm4),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['d_bps_id']))

            s5 = STLStream(packet=STLPktBuilder(pkt=data['e_to_f_pkt'] / pad(data['e_to_f_pkt']), vm=vm3),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['e_bps_id']))
            s6 = STLStream(packet=STLPktBuilder(pkt=data['f_to_e_pkt'] / pad(data['f_to_e_pkt']), vm=vm4),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['f_bps_id']))

            s7 = STLStream(packet=STLPktBuilder(pkt=data['i_to_g_pkt'] / pad(data['i_to_g_pkt']), vm=vm3),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['i_bps_id']))
            s8 = STLStream(packet=STLPktBuilder(pkt=data['g_to_i_pkt'] / pad(data['g_to_i_pkt']), vm=vm4),
                           mode=STLTXCont(pps=pps),
                           flow_stats=STLFlowStats(pg_id=data['g_bps_id']))

        else:
            s1 = STLStream(packet=STLPktBuilder(pkt=data['a_to_b_pkt'] / pad(data['a_to_b_pkt']), vm=vm1),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['a_bps_id']))
            s2 = STLStream(packet=STLPktBuilder(pkt=data['b_to_a_pkt'] / pad(data['b_to_a_pkt']), vm=vm2),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['b_bps_id']))

            s3 = STLStream(packet=STLPktBuilder(pkt=data['c_to_d_pkt'] / pad(data['c_to_d_pkt']), vm=vm3),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['c_bps_id']))
            s4 = STLStream(packet=STLPktBuilder(pkt=data['d_to_c_pkt'] / pad(data['d_to_c_pkt']), vm=vm4),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['d_bps_id']))

            s5 = STLStream(packet=STLPktBuilder(pkt=data['e_to_f_pkt'] / pad(data['e_to_f_pkt']), vm=vm5),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['e_bps_id']))
            s6 = STLStream(packet=STLPktBuilder(pkt=data['f_to_e_pkt'] / pad(data['f_to_e_pkt']), vm=vm6),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['f_bps_id']))

            s7 = STLStream(packet=STLPktBuilder(pkt=data['i_to_g_pkt'] / pad(data['i_to_g_pkt']), vm=vm7),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['i_bps_id']))
            s8 = STLStream(packet=STLPktBuilder(pkt=data['g_to_i_pkt'] / pad(data['g_to_i_pkt']), vm=vm8),
                           mode=STLTXCont(bps_L1=stream_speed / 4),
                           flow_stats=STLFlowStats(pg_id=data['g_bps_id']))

    # Сохраняем ссылки на потоки в словаре
    data['stream_a'] = s1
    data['stream_b'] = s2
    data['stream_c'] = s3
    data['stream_d'] = s4
    data['stream_e'] = s5
    data['stream_f'] = s6
    data['stream_i'] = s7
    data['stream_g'] = s8

    # Сброс статистики портов
    print('Reset ports ...', end='\r')
    trex_client.clear_stats()
    trex_client.reset_ports()

    # Добавление стримов в очередь
    print('Add streams ...', end='\r')
    for indx, data in streams.items():
        trex_client.add_stream_a(data['stream_a'])
        trex_client.add_stream_b(data['stream_b'])
        trex_client.add_stream_a(data['stream_c'])
        trex_client.add_stream_b(data['stream_d'])
        trex_client.add_stream_a(data['stream_e'])
        trex_client.add_stream_b(data['stream_f'])
        trex_client.add_stream_a(data['stream_i'])
        trex_client.add_stream_b(data['stream_g'])

    # Повторный сброс статистики и запуск стримов
    print('Start streams ...', end='\r')
    trex_client.clear_stats()
    trex_client.start_traffic(duration)

    # Ожидание окончания передачи трафика
    print('Waiting streams ...', end='\r')
    trex_client.wait_traffic()

    # Сбор статистики, возможно стоит собрать в одно
    print('Collecting stats ...', end='\r')
    stats = trex_client.get_stats()

    # Сохранение статистики в json
    print('Saving json stats ...', end='\r')
    with open('./bin/stats_generate.json', 'w') as f:
        json.dump(stats, f, indent=4)

    trex_client.disconnect()


if __name__ == '__main__':
    main()
