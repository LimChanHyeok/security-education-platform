from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, IPv6
import socketio
from datetime import datetime

# Socket.IO 클라이언트 초기화
sio = socketio.Client()

try:
    sio.connect("http://localhost:5000")
    print("[✓] Socket.IO 서버 연결 완료")
except Exception as e:
    print("❌ 서버 연결 실패:", e)
    exit(1)

# 사용할 인터페이스 이름
IFACE_NAME = r"\Device\NPF_{013ACD63-4450-47DF-AE6A-342A488F5E54}"

# 프로토콜 감지 함수
def detect_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif ARP in packet:
        return "ARP"
    elif IPv6 in packet:
        return "IPv6"
    elif IP in packet:
        return "IP"
    else:
        return "Unknown"

# 패킷 처리 함수
def handle_packet(packet):
    if IP in packet or ARP in packet or IPv6 in packet:
        try:
            proto = detect_protocol(packet)
            source = packet[IP].src if IP in packet else packet[ARP].psrc if ARP in packet else "-"
            destination = packet[IP].dst if IP in packet else packet[ARP].pdst if ARP in packet else "-"
            timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            length = len(packet)
            status = "전송됨"

            # 목적지 포트 (TCP만 해당)
            dst_port = packet[TCP].dport if TCP in packet else None

            # payload 간단하게 처리
            if hasattr(packet, "payload"):
                raw_payload = bytes(packet.payload)
                try:
                    payload = raw_payload.decode("utf-8")
                except UnicodeDecodeError:
                    payload = f"⚙️ 바이너리 데이터 ({len(raw_payload)}B)"
            else:
                payload = "-"

            # 서버로 전송
            packet_data = {
                "timestamp": timestamp,
                "source": source,
                "destination": destination,
                "protocol": proto,
                "length": length,
                "status": status,
                "payload": payload
            }

            if dst_port:  # TCP 포트 스캔 감지를 위해 포트 정보 포함
                packet_data["destination_port"] = dst_port

            sio.emit("packet", packet_data)

            # 콘솔 로그
            print(f"[전송] {timestamp} | {source} → {destination}:{dst_port or ''} ({length}B) [{proto}]")
            print(f"  └ payload: {payload[:100].replace(chr(10), ' ')}")

        except Exception as e:
            print("❌ 패킷 처리 오류:", e)

# 시작
print("[*] 실시간 패킷 감지 시작 중... 인터페이스:", IFACE_NAME)
sniff(iface=IFACE_NAME, prn=handle_packet, store=0, filter="ip or arp or tcp or udp")
