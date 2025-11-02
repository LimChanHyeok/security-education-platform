from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
from datetime import datetime
import time
from collections import defaultdict

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# 서버 상태
blocked_ips = set()
packet_counter = defaultdict(list)
portscan_counter = defaultdict(list)
threshold = 100  # DoS 기본 임계치
scan_threshold = 15  # 포트 스캔 기본 임계치
MY_IP = "192.168.0.8"

# 전체 패킷 저장
all_packets = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/explanation")
def explanation():
    return render_template("explanation.html")

@app.route('/send', methods=['POST'])
def receive_message():
    source = request.form.get("source") or request.json.get("source")
    destination = request.form.get("destination") or request.json.get("destination")
    message = request.form.get("message") or request.json.get("message")
    timestamp = datetime.now().isoformat()

    data = {
        "timestamp": timestamp,
        "source": source,
        "destination": destination,
        "protocol": "Custom",
        "length": len(message.encode("utf-8")) if message else 0,
        "status": "전송됨",
        "payload": message
    }

    all_packets.append(data)
    socketio.emit("packet", data)
    return "OK", 200

# ✅ 차단 여부 확인용 API
@app.route('/is_blocked', methods=['GET'])
def is_blocked():
    ip = request.args.get("ip")
    if not ip:
        return {"error": "Missing IP"}, 400
    return {"blocked": ip in blocked_ips}, 200

@socketio.on("packet")
def handle_sniffer_packet(data):
    ip = data.get("source")
    dst_port = data.get("destination_port")
    now = time.time()
    data["timestamp"] = datetime.now().isoformat()

    # 모든 패킷 저장
    all_packets.append(data)

    if ip == MY_IP:
        return

    # ✅ 포트 스캔 감지
    if data.get("protocol") == "TCP" and dst_port:
        portscan_counter[ip] = [t for t in portscan_counter[ip] if now - t < 1.0]
        portscan_counter[ip].append(now)
        scan_rate = len(portscan_counter[ip])

        if ip not in blocked_ips and scan_rate > scan_threshold:
            blocked_ips.add(ip)
            log_msg = (
                f"🛑 [포트 스캔 감지: TCP Connect Scan]\n"
                f"공격 IP: {ip}\n"
                f"시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"1초 내 연결 시도: {scan_rate}개 (임계치 {scan_threshold} 초과)\n"
                f"❗ TCP 포트 스캔은 대상 시스템의 열린 포트를 탐색하는 기법입니다.\n"
                f"✅ 차단됨 (해당 IP 이후 트래픽 무시됨)"
            )
            socketio.emit("log", log_msg)
            socketio.emit("blocked", list(blocked_ips))
            return

    # ✅ DoS 감지
    packet_counter[ip] = [t for t in packet_counter[ip] if now - t < 1.0]
    packet_counter[ip].append(now)
    count = len(packet_counter[ip])

    if ip not in blocked_ips and count > threshold:
        blocked_ips.add(ip)
        log_msg = (
            f"🛑 [DoS 공격 감지: UDP Flood]\n"
            f"공격 IP: {ip}\n"
            f"시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"초당 패킷 수: {count} (임계치 {threshold} 초과)\n"
            f"✅ 차단됨 (해당 IP 이후 트래픽 무시됨)"
        )
        socketio.emit("log", log_msg)
        socketio.emit("blocked", list(blocked_ips))
        return

    if ip in blocked_ips:
        data["status"] = "차단됨"
        socketio.emit("blocked_packet", data)
        return

    data["status"] = "전송됨"
    socketio.emit("packet", data)

@socketio.on("unblock")
def handle_unblock(ip):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        socketio.emit("log", f"✅ {ip}의 차단이 해제되었습니다.")
        socketio.emit("blocked", list(blocked_ips))

@socketio.on("update_threshold")
def handle_threshold_update(value):
    global threshold
    try:
        threshold = int(value)
        socketio.emit("log", f"⚙️ DoS 임계치가 {threshold}개/초로 변경되었습니다.")
    except:
        socketio.emit("log", "❌ DoS 임계치 설정 실패")

@socketio.on("update_scan_threshold")
def handle_scan_threshold_update(value):
    global scan_threshold
    try:
        scan_threshold = int(value)
        socketio.emit("log", f"🔍 포트 스캔 임계치가 {scan_threshold}개/초로 변경되었습니다.")
    except:
        socketio.emit("log", "❌ 포트 스캔 임계치 설정 실패")

@socketio.on("request_all_packets")
def send_all_packets(view_mode):
    if view_mode == "all":
        visible = all_packets
    elif view_mode == "normal":
        visible = [p for p in all_packets if p.get("status") != "차단됨"]
    elif view_mode == "blocked":
        visible = [p for p in all_packets if p.get("status") == "차단됨"]
    else:
        visible = []
    emit("packet_list", visible)

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
