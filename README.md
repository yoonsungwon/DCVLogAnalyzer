# DCV Log Analyzer

AWS DCV (NICE DCV) 로그 파일을 분석하여 성능 지표를 시각화하는 웹 기반 도구입니다.

## 📋 목차

- [개요](#개요)
- [주요 기능](#주요-기능)
- [지원 로그 유형](#지원-로그-유형)
- [파싱되는 지표](#파싱되는-지표)
- [기술 스택](#기술-스택)
- [사용 방법](#사용-방법)
- [구현 상세](#구현-상세)
- [임계값 설정](#임계값-설정)

---

## 개요

DCV Log Analyzer는 DCV Server, Agent, Client 로그 파일을 파싱하여 네트워크 성능, 화질, 지연 시간 등의 메트릭을 시계열 그래프로 시각화합니다. 문제 발생 시점을 빠르게 파악하고 원인을 분석하는 데 도움을 줍니다.

---

## 주요 기능

### 1. 로그 파일 분석
- **드래그 앤 드롭** 또는 **파일 선택**으로 로그 파일 업로드
- Server, Agent, Client 로그 자동 감지 및 분류
- 다중 파일 동시 분석 지원

### 2. 성능 지표 시각화
- **탭 인터페이스**로 Server / Agent / Client 지표 구분
- 모든 주요 메트릭을 **시계열 그래프**로 표시
- X축에 **날짜 + 시간** 표시 (MM-DD HH:MM 형식)

### 3. 차트 인터랙션
| 동작 | 설명 |
|------|------|
| **드래그** | 차트 영역을 드래그하여 해당 부분 확대 |
| **Ctrl + 휠** | 마우스 휠로 줌 인/아웃 |
| **Shift + 드래그** | 확대된 상태에서 좌우로 이동 (팬) |
| **🔍 Reset 버튼** | 줌을 원래 상태로 초기화 |

### 4. 이슈 타임라인
- 임계값 초과 시 자동으로 이슈 감지
- Warning / Critical 수준으로 분류
- 시간순 타임라인으로 표시

### 5. 요약 통계
- RTT 평균/최대값
- FPS 평균
- 대역폭 평균
- 네트워크 과부하 횟수
- 패킷 손실 이벤트 수

---

## 지원 로그 유형

### Server Log (dcv-server.log)
QUIC Transport 관련 메트릭을 포함합니다.

### Agent Log (dcv-agent.log)  
Congestion Control 및 Display Quality 메트릭을 포함합니다.

### Client Log (dcv-viewer.log)
FPS, Network Latency, Bandwidth 메트릭을 포함합니다.

---

## 파싱되는 지표

### 🖥️ Server Log 지표 (QUIC Transport)

| 차트 | 지표 | 설명 |
|------|------|------|
| **RTT** | `quic_rtt_nanos` | Round-Trip Time (last, max, avg) |
| **패킷 송수신** | `quic_sent_packets`, `quic_recv_packets`, `quic_lost_packets` | QUIC 패킷 통계 |
| **CWND Size** | `quic_cwnd_size` | 혼잡 윈도우 크기 (last, avg) |
| **Delivery Rate** | `quic_delivery_rate` | 전송률 |
| **Stream Sent** | `stream_sent` | 스트림 송신 (messages, bytes) |
| **Stream Recv** | `stream_recv` | 스트림 수신 (messages, bytes) |

**파싱 예시:**
```
2026-01-23 04:14:11,905229 [  3912:3916  ] INFO  quictransport - Connection 12 - Stats (59): quic_rtt_nanos: [last: 7871010, max: 7871010, avg: 6518031.50]
2026-01-23 04:14:11,905229 [  3912:3916  ] INFO  quictransport - Connection 12 - Stats (59): quic_cwnd_size: [last: 38850, max: 55500, avg: 43845.00]
2026-01-23 04:14:11,905229 [  3912:3916  ] INFO  quictransport - Connection 12 - Stats (59): stream_sent: [messages: [sum: 4430, last: 516, max: 561, avg: 443.00], bytes: [sum: 6942864, last: 865472, max: 865704, avg: 694286.40]]
```

### ⚙️ Agent Log 지표 (Congestion Control)

| 차트 | 지표 | 설명 |
|------|------|------|
| **Network State** | `Network_state` | overuse, underuse, normal 횟수 시계열 |
| **Bitrate** | `Bitrate` | target, sending, loss controller, delay controller, delta |
| **UDP 패킷 손실** | `UDP_packets` | received, lost, lost_fraction (min, max) |
| **Kalman Filter** | `Kalman` | filtered_delay, raw_delay, delta |
| **Display Quality** | `current_quality` | 화질, send_rate, drop_rate, frame_count |
| **Encoder Output** | `Encoder` | encoded_bytes |

**파싱 예시:**
```
2026-01-28 04:30:44,937734 [  6988:9168  ] INFO  congestion-control - cong_control_stats:6:Network_state: overuse: 0, underuse: 0, normal: 2453
2026-01-28 04:30:44,937734 [  6988:9168  ] INFO  congestion-control - cong_control_stats:6:Bitrate: target bitrate (avg ± std): 17.230 ± 0.0066 (min: 0.000)  loss controller bitrate: 18.0911 ± 0.0084   delay controller bitrate: 17.2229 ± 1.2562   sending bitrate: 1.4740 ± 0.0000   sending-target delta: -15.7556 ± -0.0066
2026-01-28 04:30:44,937734 [  6988:9168  ] INFO  congestion-control - cong_control_stats:6:UDP_packets: received: 46028, lost: 18, lost_fraction: 0.000  (min: 0.000, max: 0.750)
2026-01-28 04:30:44,937734 [  6988:9168  ] INFO  congestion-control - cong_control_stats:6:Kalman: filtered_delay (avg ± std): -0.002 ± 0.0034   raw_delay: 0.3432 ± 0.5117   delta: 0.3466 ± 0.5112
2026-01-28 04:27:46,907797 [  6988:9464  ] INFO  display - current_quality:80 quality_range:(30 - 80) drop_rate:0.00 weighted_drop_rate:0.00 send_rate:40.47 weighted_send_rate:36.17 frame_count:203 combined_rate:40.47 target_drop_rate_interval:(2.00 - 5.00)
```

### 💻 Client Log 지표 (Performance)

| 차트 | 지표 | 설명 |
|------|------|------|
| **FPS** | `FPS` | current, total, average + Low FPS 임계값 |
| **Network Latency** | `network latency` | 네트워크 지연 (ms) + Warning/Critical 임계값 |
| **Bandwidth** | `bandwidth` | current, average, peak (Kbps) |
| **네트워크 상태 요약** | - | 전체 overuse/underuse/normal 요약 도넛 차트 |

**파싱 예시:**
```
2026-01-26 03:50:56.841 |   Info|             viewer.DcvMetrics| FPS: 30 (total 1790, average 29.8333333333333); network latency: 8 ms; current bandwidth 28432.536 Kbps; average bandwidth: 32948.3834576271 Kbps, bandwidth peak: 42432.944 Kbps (in last minute)
```

---

## 기술 스택

- **HTML5** - 구조
- **CSS3** - 다크 테마 스타일링, 반응형 디자인
- **JavaScript (ES6+)** - 로직, 파싱, 차트 렌더링
- **Chart.js** - 차트 라이브러리
- **chartjs-plugin-zoom** - 줌/팬 기능
- **Hammer.js** - 터치/드래그 제스처 지원

### CDN 의존성
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.0.1"></script>
```

---

## 사용 방법

1. `index.html`을 웹 브라우저에서 엽니다.
2. DCV 로그 파일을 드래그 앤 드롭하거나 "파일 선택"을 클릭합니다.
3. 로그 유형(Server/Agent/Client)을 선택합니다.
4. "분석 시작" 버튼을 클릭합니다.
5. 결과 대시보드에서 탭을 전환하며 각 지표를 확인합니다.

### 로컬 서버 실행 (선택사항)
```bash
# Python
python -m http.server 8080

# Node.js
npx serve
```

---

## 구현 상세

### 파일 구조
```
DCVLogAnalyzer/
├── index.html       # 메인 HTML 페이지
├── styles.css       # 스타일시트 (다크 테마)
├── analyzer.js      # 핵심 로직 (파싱, 차트 렌더링)
└── README.md        # 이 문서
```

### 데이터 구조
```javascript
const results = {
    // Server log metrics (QUIC transport)
    server: {
        rtt: [],                    // quic_rtt_nanos
        lostPackets: [],            // quic_lost_packets
        cwnd: [],                   // quic_cwnd_size
        deliveryRate: [],           // quic_delivery_rate
        sentPackets: [],            // quic_sent_packets
        recvPackets: [],            // quic_recv_packets
        streamSent: [],             // stream_sent (messages, bytes)
        streamRecv: [],             // stream_recv
        dgramSent: [],              // dgram_sent
        dgramRecv: [],              // dgram_recv
        activeStreams: [],          // active_streams
    },
    // Agent log metrics (congestion control)
    agent: {
        networkState: [],           // Network_state over time
        bitrate: [],                // Bitrate stats
        delayCtrlState: [],         // Delay_ctrl_state
        lossDetector: [],           // Loss_detector_bitrate
        packetGrouper: [],          // Packet_grouper_bursts
        udpPackets: [],             // UDP_packets
        kalman: [],                 // Kalman filtered delay
        encoder: [],                // Encoder bytes
        displayQuality: [],         // Display quality metrics
    },
    // Client log metrics
    client: {
        fps: [],                    // FPS (current, total, average)
        networkLatency: [],         // network latency
        bandwidth: [],              // current, average, peak bandwidth
    },
    // Aggregated stats
    networkStateTotal: { overuse: 0, underuse: 0, normal: 0 },
    issues: [],
};
```

### 다운샘플링
대용량 로그 파일 처리 시 차트 성능을 위해 최대 200개 포인트로 다운샘플링합니다.
- 각 버킷에서 min/max 값을 보존하여 이상치를 놓치지 않음

### 차트 라벨 포맷
```javascript
// 항상 날짜 + 시간 표시: "MM-DD HH:MM"
function formatChartLabels(timestamps) {
    return timestamps.map(ts => {
        const parts = ts.split(' ');
        const date = parts[0] || '';
        const time = parts[1] || ts;
        const shortDate = date.substring(5); // 연도 제거
        const shortTime = time.substring(0, 5); // HH:MM
        return `${shortDate} ${shortTime}`;
    });
}
```

---

## 임계값 설정

```javascript
const THRESHOLDS = {
    RTT_WARNING_MS: 50,       // RTT > 50ms = Warning
    RTT_CRITICAL_MS: 100,     // RTT > 100ms = Critical
    FPS_LOW: 15,              // FPS < 15 = Low FPS warning
    PACKET_LOSS_THRESHOLD: 0.005,  // 0.5% packet loss
};
```

### 임계값 변경 방법
`analyzer.js` 파일 상단의 `THRESHOLDS` 객체를 수정합니다.

---

## 변경 이력

### v1.0 (2026-01-29)
- 초기 릴리스
- Server, Agent, Client 로그 통합 분석
- 모든 주요 성능 지표 시계열 그래프
- 차트 줌/팬 기능
- 이슈 타임라인
- 다크 테마 UI

---

## 라이선스

MIT License
