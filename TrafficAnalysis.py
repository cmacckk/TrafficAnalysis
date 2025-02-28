""" Author: cmacckk
    Date: 2025-1-26
"""

from urllib.parse import unquote, parse_qs
import argparse
import base64
import pyshark
from termcolor import colored
from rich.console import Console
from rich.theme import Theme

# 定义自定义主题
custom_theme = Theme({
    "header": "bold blue",
    "method": "bold green",
    "url": "bold magenta",
    "data": "dim yellow",
    "status": "bold red",
})

console = Console(theme=custom_theme)

def hex_colon_to_string(hex_data):
    """
    将带冒号分隔的十六进制数据转换为字符串。
    :param hex_data: 类似 "4f:52:25:33:41" 的字符串
    :return: 解码后的字符串
    """
    # 去掉冒号并将每组十六进制字符转换为字节
    byte_data = bytes.fromhex(hex_data.replace(":", ""))
    # 尝试将字节数据解码为字符串
    try:
        return byte_data.decode('utf-8')  # 根据实际编码选择合适的解码方式
    except UnicodeDecodeError:
        return f"无法解码的字节数据: {byte_data}"

def print_ant_packet(http_layer, request, response, packet, param=False):
    """
        打印蚁剑流量
    """
    data = http_layer._all_fields
    tcp_stream_id = packet.tcp.stream
    if param:
        if hasattr(http_layer, 'request_method'):
            if "http.file_data" in data:
                post_data = unquote(hex_colon_to_string(data['http.file_data']))
                parsed_post_data = parse_qs(post_data)
                _, last_value = list(parsed_post_data.items())[-1]
                result = base64.b64decode(last_value[0][2:])
                uri = data['http.request.uri']
                console.print(f"[bold][red]{uri}[/bold][/red]-[bold][yellow]{result.decode()}[/bold][/yellow]")
    else:
        # print(packet)
        # 判断是否是请求包
        if hasattr(http_layer, 'request_method'):
            if "http.file_data" in data:
                post_data = unquote(hex_colon_to_string(data['http.file_data']))
                parsed_post_data = parse_qs(post_data)
                # print(parsed_post_data)
                # 获取最后一个键值对
                _, last_value = list(parsed_post_data.items())[-1]
                req_out = f"{'='*60}AntRequestStart TCP [bold][green]StreamID:{tcp_stream_id}[/bold][/green]{'='*60}\n [bold][pink]{base64.b64decode(last_value[0][2:]).decode()}[/bold][/pink]\n{'='*60}AntRequestEnd TCP StreamID:{tcp_stream_id}{'='*60}"
                req_out_req = f"[bold][green]StreamID:{tcp_stream_id}[/green][/bold] [bold][pink]{base64.b64decode(last_value[0][2:]).decode()}[/bold][/pink]"
                if request is False and response is False:
                    console.print(req_out)
                elif request is True and response is False:
                    console.print(req_out_req)
                if request is False and response is True:
                    pass
                if request is True and response is True:
                    console.print(req_out)

                # print(packet)
                # print(f"{'='*60}Start{'='*60}\n{post_data}{'='*60}End{'='*60}\n")

        # 判断是否是响应包
        if hasattr(http_layer, 'response_code'):
            if "http.file_data" in data:
                post_data = unquote(hex_colon_to_string(data['http.file_data']))
                resp_out = f"{'='*60}AntResponse TCP [bold][green]StreamID:{tcp_stream_id}[/bold][/green]{'='*60}\n{post_data}\n{'='*60}AntResponseEnd TCP [bold][green]StreamID:{tcp_stream_id}[/bold][/green]{'='*60}"
                if request is False and response is False:
                    console.print(resp_out)
                elif request is True and response is False:
                    pass
                if request is False and response is True:
                    console.print(resp_out)
                if request is True and response is True:
                    console.print(resp_out)
                # parsed_post_data = parse_qs(post_data)
                # print(parsed_post_data)
                # 获取最后一个键值对
                # last_key, last_value = list(parsed_post_data.items())[-1]
                # print(f"{base64.b64decode(last_value[0][2:]).decode()}")
                # print(post_data)

def print_request_pack(data, packet, param=False, verbose=False):
    """
    将 JSON 数据紧凑输出（每段数据为一行）
    """
    # remove empty key
    stream_id = packet.tcp.stream
    frame_id = packet.frame_info.number
    # print(stream_id)
    not_null_key_data = {key: value for key, value in data.items() if key != ""}
    method = not_null_key_data['http.request.method']
    uri = not_null_key_data['http.request.uri']
    http_version = not_null_key_data['http.request.version']
    host = not_null_key_data['http.host']
    accept_encoding = not_null_key_data['http.accept_encoding']
    user_agent = not_null_key_data['http.user_agent']
    # content_type = not_null_key_data['http.content_type']
    # content_length = not_null_key_data['http.content_length_header']
    connection = not_null_key_data['http.connection']

    # param新增
    if param:
        if "http.file_data" in not_null_key_data:
            post_data = hex_colon_to_string(not_null_key_data['http.file_data'])
            if verbose:
                console.print(f"[bold][red]{unquote(uri)}[/bold][/red]-[bold][yellow]{post_data} {stream_id} {frame_id}[/bold][/yellow]")
            else:
                 console.print(f"[bold][red]{unquote(uri)}[/bold][/red]-[bold][yellow]{post_data}[/bold][/yellow]")
        else:
            if verbose:
                console.print(f"[bold][red]{unquote(uri)}[/bold][/red]- {stream_id} {frame_id}")
            else:
                console.print(f"[bold][red]{unquote(uri)}[/bold][/red]- ")
    else:
        if "http.file_data" in not_null_key_data:
            post_data = hex_colon_to_string(not_null_key_data['http.file_data'])
            content = f"""{method} {uri} {http_version}
Host: {host}
User-Agent: {user_agent}

{post_data}"""
        else:
            content = f"""{method} {uri} {http_version}
Host: {host}
User-Agent: {user_agent}"""
    # syntax = Syntax(content, "http", theme="monokai", line_numbers=True)

        console.print(f"{'='*60}Request StreamID: {stream_id}{'='*60}\n{unquote(content)}\n{'='*60}RequestEnd StreamID: {stream_id}{'='*60}\n")


def print_response_pack(data, packet):
    """
    将 JSON 数据紧凑输出（每段数据为一行）
    """
    # remove empty key
    stream_id = packet.tcp.stream
    not_null_key_data = {key: value for key, value in data.items() if key != ""}
    response_code = not_null_key_data['http.response.code']
    http_version = not_null_key_data['http.response.version']
    response_code_desc = not_null_key_data['http.response.code.desc']
    # host = not_null_key_data['http.host']
    date = not_null_key_data['http.date']
    server = not_null_key_data['http.server']
    
    

    if "http.file_data" in not_null_key_data:
        content = f"""{http_version} {response_code} {response_code_desc}
Server: {server}
Date: {date}

{hex_colon_to_string(not_null_key_data['http.file_data'])}"""

        console.print(f"{'='*60}Response StreamID: {stream_id}{'='*60}\n{unquote(content)}\n{'='*60}ResponseEnd StreamID: {stream_id}{'='*60}\n")


def extract_http_traffic(pcap_file, ant=False, request=False, response=False, scope=None, num=None, param=False, verbose=False):
    """
    从 pcap 文件中提取 HTTP 请求和响应并打印高亮结果
    """
    try:
        if scope is None:
            if num is None:
                cap = pyshark.FileCapture(pcap_file, display_filter='http')
            else:
                if '-' not in num:
                    start_tcp_num = int(num.split('-')[0])
                    end_tcp_num = int(num.split('-')[1])
                    display_filter = f"tcp.stream >= {start_tcp_num} && tcp.stream <= {end_tcp_num}"
                else:
                    display_filter = f"tcp.stream == {num}"
                cap = pyshark.FileCapture(pcap_file, display_filter=f'http && {display_filter}')
        else:
            if '-' not in scope:
                display_filter = f"frame.number == {scope}"
            else:
                start_frame_num = int(scope.split('-')[0])
                end_frame_num = int(scope.split('-')[1])
                display_filter = f"frame.number >= {start_frame_num} && frame.number <= {end_frame_num}"
            cap = pyshark.FileCapture(pcap_file, display_filter=f'http && {display_filter}')

        for packet in cap:
            if 'HTTP' in packet:
                http_layer = packet['HTTP']
                if ant:
                    print_ant_packet(http_layer, request, response, packet, param)
                else:
                    judge_packet_req_or_resp_output(http_layer, request, response, packet, param, verbose)

        cap.close()
    except Exception as e:
        print(colored(f"提取过程中发生错误: {e}", "red"))


def judge_packet_req_or_resp_output(http_layer, request, response, packet, param=False, verbose=False):
    """
    判断是请求包还是响应包
    """
    if param:
        if hasattr(http_layer, 'request_method'):
            print_request_pack(http_layer._all_fields, packet, param, verbose)
    else:
        if hasattr(http_layer, 'request_method'):
            if request is False and response is False:
                print_request_pack(http_layer._all_fields, packet, verbose)
            elif request is True and response is False:
                print_request_pack(http_layer._all_fields, packet, verbose)
            if request is False and response is True:
                pass
            if request is True and response is True:
                print_request_pack(http_layer._all_fields, packet, verbose)

        # 判断是否是响应包
        if hasattr(http_layer, 'response_code'):
            if request is False and response is False:
                print_response_pack(http_layer._all_fields, packet)
            elif request is False and response is True:
                print_response_pack(http_layer._all_fields, packet)
            if request is True and response is False:
                pass
            if request is True and response is True:
                print_response_pack(http_layer._all_fields, packet)

def main():
    parser = argparse.ArgumentParser(description="提取 pcap 文件中的 HTTP 流量")
    parser.add_argument("-i", "--input", required=True, help="要解析的 pcap 文件路径")
    parser.add_argument("-a", "--ant", required=False, action='store_true', help="解析蚁剑流量")
    parser.add_argument("-r", "--response", required=False, action='store_true', help="仅显示响应包")
    parser.add_argument("-q", "--request", required=False, action='store_true', help="仅显示请求包")
    parser.add_argument("-s", "--scope", type=str, help="根据frame ID范围提取数据包，例如：1-10或者12")
    parser.add_argument("-n", "--num", type=str, help="根据TCP流范围提取数据包，例如：1-10或12")
    parser.add_argument("-p", "--param", required=False, action='store_true', help="获取请求包的参数")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="输出frame id和tcp stream id")
    args = parser.parse_args()

    if args.request:
        extract_http_traffic(args.input, args.ant, request=True, scope=args.scope, num=args.num)
    elif args.response:
        extract_http_traffic(args.input, args.ant, response=True, scope=args.scope, num=args.num)
    elif args.param:
        extract_http_traffic(args.input, args.ant, request=True, scope=args.scope, num=args.num, param=True, verbose=args.verbose)
    else:
        extract_http_traffic(args.input, args.ant, scope=args.scope, num=args.num)

if __name__ == "__main__":
    main()