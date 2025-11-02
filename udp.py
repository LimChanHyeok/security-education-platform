import socket
import datetime

# 고정 포트 설정
UDP_IP = "0.0.0.0"  # 모든 인터페이스에서 수신
UDP_PORT = 5000
BUFFER_SIZE = 65535  # 최대 UDP 패킷 크기

# 소켓 생성
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"[UDP 수신기] {UDP_IP}:{UDP_PORT}에서 수신 대기 중...")

while True:
    try:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        recv_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        ip, port = addr
        size = len(data)
        print(f"[{recv_time}] ▶ From {ip}:{port} | {size} bytes | 내용: {data[:50]}")
        
        # 필요 시 여기서 packet_logger에 전달 (예: 큐에 넣기, 파일 저장 등)

    except KeyboardInterrupt:
        print("\n[UDP 수신기] 종료합니다.")
        break

sock.close()
