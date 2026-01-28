/**
 * DCV Log Analyzer - 지연 문제 분석 엔진
 * Analyzes server, agent, and client logs for latency issues
 */

// ===== Configuration =====
const THRESHOLDS = {
    RTT_WARNING_MS: 50,      // RTT > 50ms = Warning
    RTT_CRITICAL_MS: 100,    // RTT > 100ms = Critical
    FPS_LOW: 15,             // FPS < 15 = Low FPS warning
    PACKET_LOSS_THRESHOLD: 0.005,  // 0.5% packet loss
};

// ===== Global State =====
let uploadedFiles = [];
let analysisResults = null;
let charts = {};

// ===== DOM Elements =====
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const configFile = document.getElementById('configFile');
const filesList = document.getElementById('filesList');
const analyzeBtn = document.getElementById('analyzeBtn');
const resultsSection = document.getElementById('resultsSection');
const loadingOverlay = document.getElementById('loadingOverlay');

// ===== Event Listeners =====
document.addEventListener('DOMContentLoaded', initializeApp);

function initializeApp() {
    setupTabs();
    setupDropZone();
    setupConfigUpload();
    setupAnalyzeButton();
}

// Tab switching
function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(`${btn.dataset.tab}-tab`).classList.add('active');
        });
    });
}

// Drop zone for file upload
function setupDropZone() {
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });

    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });
}

// Config file upload
function setupConfigUpload() {
    configFile.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        try {
            const text = await file.text();
            const config = JSON.parse(text);
            console.log('Config loaded:', config);
            alert('설정파일이 로드되었습니다.\n\n참고: 웹 보안 정책으로 인해 설정파일의 로컬 경로에서 직접 파일을 읽을 수 없습니다.\n대신 해당 로그 파일들을 드래그앤드롭으로 업로드해주세요.');
        } catch (err) {
            alert('설정파일 파싱 오류: ' + err.message);
        }
    });
}

// Analyze button
function setupAnalyzeButton() {
    analyzeBtn.addEventListener('click', startAnalysis);
}

// ===== File Handling =====
function handleFiles(files) {
    for (const file of files) {
        const type = detectLogType(file.name);
        if (type) {
            uploadedFiles.push({ file, type, name: file.name });
            renderFilesList();
        }
    }
    updateAnalyzeButton();
}

function detectLogType(filename) {
    const lower = filename.toLowerCase();
    if (lower.includes('server')) return 'server';
    if (lower.includes('agent')) return 'agent';
    if (lower.includes('client') || lower.includes('_client_')) return 'client';
    if (lower.endsWith('.log') || lower.endsWith('.txt')) return 'unknown';
    return null;
}

function renderFilesList() {
    filesList.innerHTML = uploadedFiles.map((f, idx) => `
        <div class="file-item">
            <div class="file-name">
                <span class="file-type ${f.type}">${f.type.toUpperCase()}</span>
                <span>${f.name}</span>
            </div>
            <button class="remove-btn" onclick="removeFile(${idx})">×</button>
        </div>
    `).join('');
}

function removeFile(idx) {
    uploadedFiles.splice(idx, 1);
    renderFilesList();
    updateAnalyzeButton();
}

function updateAnalyzeButton() {
    analyzeBtn.disabled = uploadedFiles.length === 0;
}

// ===== Analysis Engine =====
async function startAnalysis() {
    loadingOverlay.style.display = 'flex';

    try {
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
            // Aggregated stats for summary cards
            networkStateTotal: { overuse: 0, underuse: 0, normal: 0 },
            issues: [],
        };

        for (const { file, type } of uploadedFiles) {
            const content = await file.text();
            const lines = content.split('\n');

            switch (type) {
                case 'server':
                    parseServerLog(lines, results);
                    break;
                case 'agent':
                    parseAgentLog(lines, results);
                    break;
                case 'client':
                    parseClientLog(lines, results);
                    break;
                default:
                    // Try all parsers for unknown files
                    parseServerLog(lines, results);
                    parseAgentLog(lines, results);
                    parseClientLog(lines, results);
            }
        }

        analysisResults = results;
        displayResults(results);

    } catch (error) {
        console.error('Analysis error:', error);
        alert('분석 중 오류 발생: ' + error.message);
    } finally {
        loadingOverlay.style.display = 'none';
    }
}

// ===== Server Log Parser =====
// Parses ALL QUIC transport metrics
function parseServerLog(lines, results) {
    const timestampRegex = /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/;

    // Generic stat parser: [last: X, max: Y, avg: Z] or [sum: X, last: Y, max: Z, avg: W]
    const parseStats = (line, statName) => {
        const regex = new RegExp(`${statName}:\\s*\\[([^\\]]+)\\]`);
        const match = line.match(regex);
        if (!match) return null;

        const statsStr = match[1];
        const stats = {};

        // Parse key: value pairs
        const pairs = statsStr.match(/(\w+):\s*[\d.-]+/g) || [];
        pairs.forEach(pair => {
            const [key, val] = pair.split(':').map(s => s.trim());
            stats[key] = parseFloat(val);
        });

        return stats;
    };

    // Parse nested stats: [messages: [...], bytes: [...]]
    const parseNestedStats = (line, statName) => {
        const regex = new RegExp(`${statName}:\\s*\\[messages:\\s*\\[([^\\]]+)\\],\\s*bytes:\\s*\\[([^\\]]+)\\]\\]`);
        const match = line.match(regex);
        if (!match) return null;

        const parseInner = (str) => {
            const stats = {};
            const pairs = str.match(/(\w+):\s*[\d.-]+/g) || [];
            pairs.forEach(pair => {
                const [key, val] = pair.split(':').map(s => s.trim());
                stats[key] = parseFloat(val);
            });
            return stats;
        };

        return {
            messages: parseInner(match[1]),
            bytes: parseInner(match[2])
        };
    };

    for (const line of lines) {
        if (!line.includes('quictransport')) continue;

        const tsMatch = line.match(timestampRegex);
        if (!tsMatch) continue;
        const timestamp = tsMatch[1];

        // RTT (nanoseconds -> milliseconds)
        const rttStats = parseStats(line, 'quic_rtt_nanos');
        if (rttStats) {
            const entry = {
                timestamp,
                last: (rttStats.last || 0) / 1_000_000,
                max: (rttStats.max || 0) / 1_000_000,
                avg: (rttStats.avg || 0) / 1_000_000
            };
            results.server.rtt.push(entry);

            // Check for RTT anomalies
            if (entry.last > THRESHOLDS.RTT_CRITICAL_MS) {
                results.issues.push({
                    timestamp, type: 'critical', category: 'RTT',
                    message: `RTT ${entry.last.toFixed(2)}ms (Critical: >${THRESHOLDS.RTT_CRITICAL_MS}ms)`
                });
            } else if (entry.last > THRESHOLDS.RTT_WARNING_MS) {
                results.issues.push({
                    timestamp, type: 'warning', category: 'RTT',
                    message: `RTT ${entry.last.toFixed(2)}ms (Warning: >${THRESHOLDS.RTT_WARNING_MS}ms)`
                });
            }
        }

        // Lost packets
        const lostStats = parseStats(line, 'quic_lost_packets');
        if (lostStats) {
            results.server.lostPackets.push({ timestamp, ...lostStats });
        }

        // CWND size
        const cwndStats = parseStats(line, 'quic_cwnd_size');
        if (cwndStats) {
            results.server.cwnd.push({ timestamp, ...cwndStats });
        }

        // Delivery rate
        const deliveryStats = parseStats(line, 'quic_delivery_rate');
        if (deliveryStats) {
            results.server.deliveryRate.push({ timestamp, ...deliveryStats });
        }

        // Sent/Recv packets
        const sentStats = parseStats(line, 'quic_sent_packets');
        if (sentStats) {
            results.server.sentPackets.push({ timestamp, ...sentStats });
        }

        const recvStats = parseStats(line, 'quic_recv_packets');
        if (recvStats) {
            results.server.recvPackets.push({ timestamp, ...recvStats });
        }

        // Stream sent/recv
        const streamSentStats = parseNestedStats(line, 'stream_sent');
        if (streamSentStats) {
            results.server.streamSent.push({ timestamp, ...streamSentStats });
        }

        const streamRecvStats = parseNestedStats(line, 'stream_recv');
        if (streamRecvStats) {
            results.server.streamRecv.push({ timestamp, ...streamRecvStats });
        }

        // Datagram sent/recv
        const dgramSentStats = parseNestedStats(line, 'dgram_sent');
        if (dgramSentStats) {
            results.server.dgramSent.push({ timestamp, ...dgramSentStats });
        }

        const dgramRecvStats = parseNestedStats(line, 'dgram_recv');
        if (dgramRecvStats) {
            results.server.dgramRecv.push({ timestamp, ...dgramRecvStats });
        }

        // Active streams
        const activeStats = parseStats(line, 'active_streams');
        if (activeStats) {
            results.server.activeStreams.push({ timestamp, ...activeStats });
        }
    }
}

// ===== Agent Log Parser =====
// Parses ALL congestion control and display metrics
function parseAgentLog(lines, results) {
    const timestampRegex = /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/;

    for (const line of lines) {
        const tsMatch = line.match(timestampRegex);
        const timestamp = tsMatch ? tsMatch[1] : null;

        // Network state: overuse, underuse, normal
        const netMatch = line.match(/Network_state:\s*overuse:\s*(\d+),\s*underuse:\s*(\d+),\s*normal:\s*(\d+)/);
        if (netMatch && timestamp) {
            const overuse = parseInt(netMatch[1]);
            const underuse = parseInt(netMatch[2]);
            const normal = parseInt(netMatch[3]);

            results.agent.networkState.push({ timestamp, overuse, underuse, normal });
            results.networkStateTotal.overuse += overuse;
            results.networkStateTotal.underuse += underuse;
            results.networkStateTotal.normal += normal;

            if (overuse > 0) {
                results.issues.push({
                    timestamp, type: 'warning', category: 'Network',
                    message: `네트워크 과부하 감지 (overuse: ${overuse})`
                });
            }
        }

        // Bitrate: target, loss controller, delay controller, sending, delta
        const bitrateMatch = line.match(/Bitrate:\s*target bitrate.*?:\s*([\d.]+)\s*±\s*([\d.]+).*loss controller.*?:\s*([\d.]+)\s*±\s*([\d.]+).*delay controller.*?:\s*([\d.]+)\s*±\s*([\d.]+).*sending bitrate:\s*([\d.]+)\s*±\s*([\d.]+).*delta:\s*([\d.-]+)\s*±\s*([\d.-]+)/);
        if (bitrateMatch && timestamp) {
            results.agent.bitrate.push({
                timestamp,
                targetBitrate: parseFloat(bitrateMatch[1]),
                targetStd: parseFloat(bitrateMatch[2]),
                lossController: parseFloat(bitrateMatch[3]),
                lossControllerStd: parseFloat(bitrateMatch[4]),
                delayController: parseFloat(bitrateMatch[5]),
                delayControllerStd: parseFloat(bitrateMatch[6]),
                sendingBitrate: parseFloat(bitrateMatch[7]),
                sendingStd: parseFloat(bitrateMatch[8]),
                delta: parseFloat(bitrateMatch[9]),
                deltaStd: parseFloat(bitrateMatch[10])
            });
        }

        // Delay control state: increase, decrease, hold
        const delayCtrlMatch = line.match(/Delay_ctrl_state:\s*increase:\s*(\d+),\s*decrease:\s*(\d+),\s*hold:\s*(\d+)/);
        if (delayCtrlMatch && timestamp) {
            results.agent.delayCtrlState.push({
                timestamp,
                increase: parseInt(delayCtrlMatch[1]),
                decrease: parseInt(delayCtrlMatch[2]),
                hold: parseInt(delayCtrlMatch[3])
            });
        }

        // Loss detector bitrate: decrease, increase, updates
        const lossDetectorMatch = line.match(/Loss_detector_bitrate:\s*decrease:\s*(\d+),\s*increase:\s*(\d+),\s*updates:\s*(\d+)/);
        if (lossDetectorMatch && timestamp) {
            results.agent.lossDetector.push({
                timestamp,
                decrease: parseInt(lossDetectorMatch[1]),
                increase: parseInt(lossDetectorMatch[2]),
                updates: parseInt(lossDetectorMatch[3])
            });
        }

        // Packet grouper bursts
        const packetGrouperMatch = line.match(/Packet_grouper_bursts:\s*min_len:\s*(\d+),\s*max_len:\s*(\d+),\s*avg_len:\s*([\d.]+)\s*count:\s*(\d+)/);
        if (packetGrouperMatch && timestamp) {
            results.agent.packetGrouper.push({
                timestamp,
                minLen: parseInt(packetGrouperMatch[1]),
                maxLen: parseInt(packetGrouperMatch[2]),
                avgLen: parseFloat(packetGrouperMatch[3]),
                count: parseInt(packetGrouperMatch[4])
            });
        }

        // UDP packets: received, lost, lost_fraction (min, max)
        const udpMatch = line.match(/UDP_packets:\s*received:\s*(\d+),\s*lost:\s*(\d+),\s*lost_fraction:\s*([\d.]+)\s*\(min:\s*([\d.]+),\s*max:\s*([\d.]+)\)/);
        if (udpMatch && timestamp) {
            const received = parseInt(udpMatch[1]);
            const lost = parseInt(udpMatch[2]);
            const lostFraction = parseFloat(udpMatch[3]);
            const minFraction = parseFloat(udpMatch[4]);
            const maxFraction = parseFloat(udpMatch[5]);

            results.agent.udpPackets.push({
                timestamp, received, lost, lostFraction, minFraction, maxFraction
            });

            if (lostFraction > THRESHOLDS.PACKET_LOSS_THRESHOLD) {
                results.issues.push({
                    timestamp, type: 'critical', category: 'Packet Loss',
                    message: `패킷 손실 ${(lostFraction * 100).toFixed(2)}% (${lost}/${received})`
                });
            }
        }

        // Kalman filter: filtered_delay, raw_delay, delta
        const kalmanMatch = line.match(/Kalman:\s*filtered_delay.*?:\s*([\d.-]+)\s*±\s*([\d.]+)\s*raw_delay:\s*([\d.-]+)\s*±\s*([\d.]+)\s*delta:\s*([\d.-]+)\s*±\s*([\d.]+)/);
        if (kalmanMatch && timestamp) {
            results.agent.kalman.push({
                timestamp,
                filteredDelay: parseFloat(kalmanMatch[1]),
                filteredDelayStd: parseFloat(kalmanMatch[2]),
                rawDelay: parseFloat(kalmanMatch[3]),
                rawDelayStd: parseFloat(kalmanMatch[4]),
                delta: parseFloat(kalmanMatch[5]),
                deltaStd: parseFloat(kalmanMatch[6])
            });
        }

        // Encoder: encoded bytes
        const encoderMatch = line.match(/Encoder:\s*encoded bytes:\s*(\d+)/);
        if (encoderMatch && timestamp) {
            results.agent.encoder.push({
                timestamp,
                encodedBytes: parseInt(encoderMatch[1])
            });
        }

        // Display quality: current_quality, quality_range, drop_rate, send_rate, etc.
        const qualityMatch = line.match(/current_quality:(\d+)\s*quality_range:\((\d+)\s*-\s*(\d+)\)\s*drop_rate:([\d.]+)\s*weighted_drop_rate:([\d.]+)\s*send_rate:([\d.]+)\s*weighted_send_rate:([\d.]+)\s*frame_count:(\d+)\s*combined_rate:([\d.]+)/);
        if (qualityMatch && timestamp) {
            const quality = parseInt(qualityMatch[1]);
            results.agent.displayQuality.push({
                timestamp,
                currentQuality: quality,
                qualityMin: parseInt(qualityMatch[2]),
                qualityMax: parseInt(qualityMatch[3]),
                dropRate: parseFloat(qualityMatch[4]),
                weightedDropRate: parseFloat(qualityMatch[5]),
                sendRate: parseFloat(qualityMatch[6]),
                weightedSendRate: parseFloat(qualityMatch[7]),
                frameCount: parseInt(qualityMatch[8]),
                combinedRate: parseFloat(qualityMatch[9])
            });

            if (quality < 50) {
                results.issues.push({
                    timestamp, type: 'warning', category: 'Quality',
                    message: `화질 저하 감지 (quality: ${quality})`
                });
            }
        }
    }
}

// ===== Client Log Parser =====
// Parses ALL client metrics (FPS, bandwidth, latency)
function parseClientLog(lines, results) {
    const timestampRegex = /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/;

    // FPS: 30 (total 1790, average 29.83); network latency: 8 ms; current bandwidth 28432.536 Kbps; average bandwidth: 32948.38 Kbps, bandwidth peak: 42432.944 Kbps
    const metricsRegex = /FPS:\s*(\d+)\s*\(total\s*(\d+),\s*average\s*([\d.]+)\);\s*network latency:\s*(\d+)\s*ms;\s*current bandwidth\s*([\d.]+)\s*Kbps;\s*average bandwidth:\s*([\d.]+)\s*Kbps,\s*bandwidth peak:\s*([\d.]+)\s*Kbps/;
    const displayLatencyRegex = /Indicator\s+display_latency\s+changed\s+to\s+status\s+(\w+)/;
    const frameLossRegex = /Indicator\s+frame_loss\s+changed\s+to\s+status\s+(\w+)/;

    for (const line of lines) {
        const tsMatch = line.match(timestampRegex);
        const timestamp = tsMatch ? tsMatch[1] : null;

        // FPS and bandwidth metrics
        const metricsMatch = line.match(metricsRegex);
        if (metricsMatch && timestamp) {
            const fps = parseInt(metricsMatch[1]);
            const fpsTotal = parseInt(metricsMatch[2]);
            const fpsAverage = parseFloat(metricsMatch[3]);
            const networkLatency = parseInt(metricsMatch[4]);
            const currentBandwidth = parseFloat(metricsMatch[5]);
            const avgBandwidth = parseFloat(metricsMatch[6]);
            const peakBandwidth = parseFloat(metricsMatch[7]);

            results.client.fps.push({
                timestamp,
                value: fps,
                total: fpsTotal,
                average: fpsAverage
            });

            results.client.networkLatency.push({
                timestamp,
                value: networkLatency
            });

            results.client.bandwidth.push({
                timestamp,
                current: currentBandwidth,
                average: avgBandwidth,
                peak: peakBandwidth
            });

            // Low FPS warning
            if (fps < THRESHOLDS.FPS_LOW && fps > 0) {
                results.issues.push({
                    timestamp, type: 'warning', category: 'FPS',
                    message: `낮은 FPS: ${fps} (평균: ${fpsAverage.toFixed(1)}, 기준: ${THRESHOLDS.FPS_LOW})`
                });
            }

            // High network latency
            if (networkLatency > THRESHOLDS.RTT_CRITICAL_MS) {
                results.issues.push({
                    timestamp, type: 'critical', category: 'Latency',
                    message: `높은 네트워크 지연: ${networkLatency}ms (Critical: >${THRESHOLDS.RTT_CRITICAL_MS}ms)`
                });
            } else if (networkLatency > THRESHOLDS.RTT_WARNING_MS) {
                results.issues.push({
                    timestamp, type: 'warning', category: 'Latency',
                    message: `네트워크 지연 경고: ${networkLatency}ms (Warning: >${THRESHOLDS.RTT_WARNING_MS}ms)`
                });
            }
        }

        // Display latency status change
        const displayMatch = line.match(displayLatencyRegex);
        if (displayMatch && timestamp && displayMatch[1].toLowerCase() !== 'normal') {
            results.issues.push({
                timestamp, type: 'warning', category: 'Display',
                message: `디스플레이 지연 상태: ${displayMatch[1]}`
            });
        }

        // Frame loss status change
        const frameMatch = line.match(frameLossRegex);
        if (frameMatch && timestamp && frameMatch[1].toLowerCase() !== 'normal') {
            results.issues.push({
                timestamp, type: 'critical', category: 'Frame',
                message: `프레임 손실 상태: ${frameMatch[1]}`
            });
        }
    }
}

// ===== Display Results =====
function displayResults(results) {
    resultsSection.style.display = 'block';

    // Calculate statistics from new structure
    const rttValues = results.server.rtt.map(r => r.last);
    const rttAvg = rttValues.length ? (rttValues.reduce((a, b) => a + b, 0) / rttValues.length) : 0;
    const rttMax = rttValues.length ? Math.max(...rttValues) : 0;
    const rttAnomalies = results.issues.filter(i => i.category === 'RTT').length;

    const fpsValues = results.client.fps.map(f => f.value);
    const fpsAvg = fpsValues.length ? (fpsValues.reduce((a, b) => a + b, 0) / fpsValues.length) : 0;

    const bwValues = results.client.bandwidth.map(b => b.current);
    const bwAvg = bwValues.length ? (bwValues.reduce((a, b) => a + b, 0) / bwValues.length) : 0;

    const warnings = results.issues.filter(i => i.type === 'warning').length;
    const criticals = results.issues.filter(i => i.type === 'critical').length;

    // Update summary cards
    document.getElementById('rttAvg').textContent = rttAvg.toFixed(2) + ' ms';
    document.getElementById('rttMax').textContent = rttMax.toFixed(2) + ' ms';
    document.getElementById('rttAnomalies').textContent = rttAnomalies;
    document.getElementById('fpsAvg').textContent = fpsAvg.toFixed(1);
    document.getElementById('bwAvg').textContent = (bwAvg / 1000).toFixed(1) + ' Mbps';
    document.getElementById('netOveruse').textContent = results.networkStateTotal.overuse;

    const udpLossEvents = results.agent.udpPackets.filter(p => p.lostFraction > 0).length;
    document.getElementById('packetLoss').textContent = udpLossEvents > 0 ? udpLossEvents + ' events' : '0';
    document.getElementById('issueWarning').textContent = warnings;
    document.getElementById('issueCritical').textContent = criticals;

    // Setup chart tabs
    setupChartTabs();

    // Render all charts
    renderAllCharts(results);

    // Render timeline
    renderTimeline(results.issues);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Setup chart tab switching
function setupChartTabs() {
    const chartTabBtns = document.querySelectorAll('.chart-tab-btn');
    chartTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            chartTabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            document.querySelectorAll('.chart-tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(`${btn.dataset.chartTab}-charts`).classList.add('active');
        });
    });
}

// ===== Chart Rendering =====

// Format timestamp for chart labels - always show date with time
function formatChartLabels(timestamps) {
    return timestamps.map(ts => {
        const parts = ts.split(' ');
        const date = parts[0] || '';
        const time = parts[1] || ts;

        // Always show date (MM-DD) + time (HH:MM)
        const shortDate = date.substring(5); // Remove year (2026-01-23 -> 01-23)
        const shortTime = time.substring(0, 5); // HH:MM only (avoid clutter)
        return `${shortDate} ${shortTime}`;
    });
}

// Downsample data while preserving important points (min/max in each bucket)
function downsampleData(data, maxPoints) {
    if (data.length <= maxPoints) return data;

    const bucketSize = Math.ceil(data.length / maxPoints);
    const sampled = [];

    for (let i = 0; i < data.length; i += bucketSize) {
        const bucket = data.slice(i, Math.min(i + bucketSize, data.length));

        // Keep first, last, min, and max points from each bucket
        if (bucket.length === 1) {
            sampled.push(bucket[0]);
        } else {
            // Find min and max by 'last' or 'value' property
            const getValue = (item) => item.last !== undefined ? item.last : item.value;
            let minItem = bucket[0];
            let maxItem = bucket[0];

            bucket.forEach(item => {
                if (getValue(item) < getValue(minItem)) minItem = item;
                if (getValue(item) > getValue(maxItem)) maxItem = item;
            });

            // Add in chronological order (first, then min/max, then last)
            sampled.push(bucket[0]);
            if (minItem !== bucket[0] && minItem !== bucket[bucket.length - 1]) {
                sampled.push(minItem);
            }
            if (maxItem !== bucket[0] && maxItem !== bucket[bucket.length - 1] && maxItem !== minItem) {
                sampled.push(maxItem);
            }
            if (bucket.length > 1) {
                sampled.push(bucket[bucket.length - 1]);
            }
        }
    }

    return sampled;
}

// Get evenly distributed sample indices
function getSampleIndices(dataLength, maxPoints) {
    if (dataLength <= maxPoints) {
        return Array.from({ length: dataLength }, (_, i) => i);
    }

    const step = (dataLength - 1) / (maxPoints - 1);
    const indices = [];
    for (let i = 0; i < maxPoints; i++) {
        indices.push(Math.round(i * step));
    }
    return indices;
}

function renderAllCharts(results) {
    // Destroy existing charts
    Object.values(charts).forEach(chart => chart.destroy());
    charts = {};

    const MAX_POINTS = 200;

    // Helper to create a simple line chart
    const createLineChart = (canvasId, chartKey, data, labelField, datasets, options = {}) => {
        const canvas = document.getElementById(canvasId);
        if (!canvas || data.length === 0) return;

        const ctx = canvas.getContext('2d');
        const sampled = downsampleData(data.map(d => ({ ...d, value: d[labelField] || 0 })), MAX_POINTS);
        const labels = formatChartLabels(sampled.map(d => d.timestamp));

        const chartDatasets = datasets.map(ds => ({
            label: ds.label,
            data: sampled.map(d => ds.getValue(d)),
            borderColor: ds.color,
            backgroundColor: ds.bgColor || ds.color.replace(')', ', 0.1)').replace('rgb', 'rgba'),
            fill: ds.fill !== false,
            tension: 0.4,
            pointRadius: ds.pointRadius !== undefined ? ds.pointRadius : 2,
            ...ds.extra
        }));

        charts[chartKey] = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets: chartDatasets },
            options: { ...getChartOptions(), ...options }
        });
    };

    // ========== SERVER CHARTS ==========

    // Server RTT Chart
    if (results.server.rtt.length > 0) {
        const canvas = document.getElementById('serverRttChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = downsampleData(results.server.rtt, MAX_POINTS);
            const labels = formatChartLabels(sampled.map(r => r.timestamp));

            charts.serverRtt = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'RTT Last (ms)',
                        data: sampled.map(r => r.last),
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'RTT Avg (ms)',
                        data: sampled.map(r => r.avg),
                        borderColor: '#60a5fa',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }, {
                        label: 'Warning',
                        data: Array(sampled.length).fill(THRESHOLDS.RTT_WARNING_MS),
                        borderColor: '#f59e0b',
                        borderDash: [5, 5],
                        pointRadius: 0,
                        fill: false
                    }, {
                        label: 'Critical',
                        data: Array(sampled.length).fill(THRESHOLDS.RTT_CRITICAL_MS),
                        borderColor: '#ef4444',
                        borderDash: [5, 5],
                        pointRadius: 0,
                        fill: false
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Server Packets Chart
    if (results.server.sentPackets.length > 0 || results.server.recvPackets.length > 0) {
        const canvas = document.getElementById('serverPacketsChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const data = results.server.sentPackets.length >= results.server.recvPackets.length
                ? results.server.sentPackets : results.server.recvPackets;
            const indices = getSampleIndices(data.length, MAX_POINTS);
            const labels = formatChartLabels(indices.map(i => data[i].timestamp));

            const datasets = [];
            if (results.server.sentPackets.length > 0) {
                datasets.push({
                    label: 'Sent (sum)',
                    data: indices.map(i => results.server.sentPackets[Math.min(i, results.server.sentPackets.length - 1)]?.sum || 0),
                    borderColor: '#10b981',
                    fill: false,
                    tension: 0.4
                });
            }
            if (results.server.recvPackets.length > 0) {
                datasets.push({
                    label: 'Recv (sum)',
                    data: indices.map(i => results.server.recvPackets[Math.min(i, results.server.recvPackets.length - 1)]?.sum || 0),
                    borderColor: '#8b5cf6',
                    fill: false,
                    tension: 0.4
                });
            }
            if (results.server.lostPackets.length > 0) {
                datasets.push({
                    label: 'Lost (sum)',
                    data: indices.map(i => results.server.lostPackets[Math.min(i, results.server.lostPackets.length - 1)]?.sum || 0),
                    borderColor: '#ef4444',
                    fill: false,
                    tension: 0.4
                });
            }

            charts.serverPackets = new Chart(ctx, {
                type: 'line',
                data: { labels, datasets },
                options: getChartOptions()
            });
        }
    }

    // Server CWND Chart
    if (results.server.cwnd.length > 0) {
        const canvas = document.getElementById('serverCwndChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = downsampleData(results.server.cwnd.map(c => ({ ...c, value: c.last })), MAX_POINTS);
            const labels = formatChartLabels(sampled.map(c => c.timestamp));

            charts.serverCwnd = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'CWND Last',
                        data: sampled.map(c => c.last),
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'CWND Avg',
                        data: sampled.map(c => c.avg),
                        borderColor: '#22d3ee',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Server Delivery Rate Chart
    if (results.server.deliveryRate.length > 0) {
        const canvas = document.getElementById('serverDeliveryChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = downsampleData(results.server.deliveryRate.map(d => ({ ...d, value: d.last })), MAX_POINTS);
            const labels = formatChartLabels(sampled.map(d => d.timestamp));

            charts.serverDelivery = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Delivery Rate (Last)',
                        data: sampled.map(d => d.last),
                        borderColor: '#a855f7',
                        backgroundColor: 'rgba(168, 85, 247, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Server Stream Sent Chart
    if (results.server.streamSent.length > 0) {
        const canvas = document.getElementById('serverStreamSentChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.server.streamSent.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(s => s.timestamp));

            charts.serverStreamSent = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Bytes (sum)',
                        data: sampled.map(s => s.bytes?.sum || 0),
                        borderColor: '#f97316',
                        backgroundColor: 'rgba(249, 115, 22, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Server Stream Recv Chart
    if (results.server.streamRecv.length > 0) {
        const canvas = document.getElementById('serverStreamRecvChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.server.streamRecv.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(s => s.timestamp));

            charts.serverStreamRecv = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Bytes (sum)',
                        data: sampled.map(s => s.bytes?.sum || 0),
                        borderColor: '#14b8a6',
                        backgroundColor: 'rgba(20, 184, 166, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // ========== AGENT CHARTS ==========

    // Agent Network State Chart (time series)
    if (results.agent.networkState.length > 0) {
        const canvas = document.getElementById('agentNetStateChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.agent.networkState.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(s => s.timestamp));

            charts.agentNetState = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Normal',
                        data: sampled.map(s => s.normal),
                        borderColor: '#10b981',
                        fill: false,
                        tension: 0.4
                    }, {
                        label: 'Overuse',
                        data: sampled.map(s => s.overuse),
                        borderColor: '#ef4444',
                        fill: false,
                        tension: 0.4
                    }, {
                        label: 'Underuse',
                        data: sampled.map(s => s.underuse),
                        borderColor: '#f59e0b',
                        fill: false,
                        tension: 0.4
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Agent Bitrate Chart
    if (results.agent.bitrate.length > 0) {
        const canvas = document.getElementById('agentBitrateChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.agent.bitrate.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(b => b.timestamp));

            charts.agentBitrate = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Target Bitrate',
                        data: sampled.map(b => b.targetBitrate),
                        borderColor: '#3b82f6',
                        fill: false,
                        tension: 0.4
                    }, {
                        label: 'Sending Bitrate',
                        data: sampled.map(b => b.sendingBitrate),
                        borderColor: '#10b981',
                        fill: false,
                        tension: 0.4
                    }, {
                        label: 'Loss Controller',
                        data: sampled.map(b => b.lossController),
                        borderColor: '#f59e0b',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Agent UDP Packets Chart
    if (results.agent.udpPackets.length > 0) {
        const canvas = document.getElementById('agentUdpChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.agent.udpPackets.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(u => u.timestamp));

            charts.agentUdp = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Lost Fraction (%)',
                        data: sampled.map(u => u.lostFraction * 100),
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Max Loss (%)',
                        data: sampled.map(u => u.maxFraction * 100),
                        borderColor: '#f97316',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Agent Kalman Filter Chart
    if (results.agent.kalman.length > 0) {
        const canvas = document.getElementById('agentKalmanChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.agent.kalman.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(k => k.timestamp));

            charts.agentKalman = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Filtered Delay',
                        data: sampled.map(k => k.filteredDelay),
                        borderColor: '#8b5cf6',
                        fill: false,
                        tension: 0.4
                    }, {
                        label: 'Raw Delay',
                        data: sampled.map(k => k.rawDelay),
                        borderColor: '#a855f7',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Agent Quality Chart
    if (results.agent.displayQuality.length > 0) {
        const canvas = document.getElementById('agentQualityChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.agent.displayQuality.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(q => q.timestamp));

            charts.agentQuality = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Current Quality',
                        data: sampled.map(q => q.currentQuality),
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Send Rate',
                        data: sampled.map(q => q.sendRate),
                        borderColor: '#10b981',
                        fill: false,
                        tension: 0.4,
                        yAxisID: 'y1'
                    }]
                },
                options: {
                    ...getChartOptions(),
                    scales: {
                        x: { display: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#6a6a7a' } },
                        y: { display: true, position: 'left', grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#6a6a7a' } },
                        y1: { display: true, position: 'right', grid: { drawOnChartArea: false }, ticks: { color: '#6a6a7a' } }
                    }
                }
            });
        }
    }

    // Agent Encoder Chart
    if (results.agent.encoder.length > 0) {
        const canvas = document.getElementById('agentEncoderChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = results.agent.encoder.slice(-MAX_POINTS);
            const labels = formatChartLabels(sampled.map(e => e.timestamp));

            charts.agentEncoder = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Encoded Bytes',
                        data: sampled.map(e => e.encodedBytes),
                        borderColor: '#f97316',
                        backgroundColor: 'rgba(249, 115, 22, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // ========== CLIENT CHARTS ==========

    // Client FPS Chart
    if (results.client.fps.length > 0) {
        const canvas = document.getElementById('clientFpsChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = downsampleData(results.client.fps, MAX_POINTS);
            const labels = formatChartLabels(sampled.map(f => f.timestamp));

            charts.clientFps = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'FPS (Current)',
                        data: sampled.map(f => f.value),
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'FPS (Average)',
                        data: sampled.map(f => f.average),
                        borderColor: '#34d399',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }, {
                        label: 'Low FPS Threshold',
                        data: Array(sampled.length).fill(THRESHOLDS.FPS_LOW),
                        borderColor: '#f59e0b',
                        borderDash: [5, 5],
                        pointRadius: 0,
                        fill: false
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Client Network Latency Chart
    if (results.client.networkLatency.length > 0) {
        const canvas = document.getElementById('clientLatencyChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = downsampleData(results.client.networkLatency, MAX_POINTS);
            const labels = formatChartLabels(sampled.map(l => l.timestamp));

            charts.clientLatency = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Network Latency (ms)',
                        data: sampled.map(l => l.value),
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Warning',
                        data: Array(sampled.length).fill(THRESHOLDS.RTT_WARNING_MS),
                        borderColor: '#f59e0b',
                        borderDash: [5, 5],
                        pointRadius: 0,
                        fill: false
                    }, {
                        label: 'Critical',
                        data: Array(sampled.length).fill(THRESHOLDS.RTT_CRITICAL_MS),
                        borderColor: '#ef4444',
                        borderDash: [5, 5],
                        pointRadius: 0,
                        fill: false
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Client Bandwidth Chart
    if (results.client.bandwidth.length > 0) {
        const canvas = document.getElementById('clientBandwidthChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            const sampled = downsampleData(results.client.bandwidth.map(b => ({ ...b, value: b.current })), MAX_POINTS);
            const labels = formatChartLabels(sampled.map(b => b.timestamp));

            charts.clientBandwidth = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Current (Kbps)',
                        data: sampled.map(b => b.current),
                        borderColor: '#8b5cf6',
                        backgroundColor: 'rgba(139, 92, 246, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Average (Kbps)',
                        data: sampled.map(b => b.average),
                        borderColor: '#a78bfa',
                        borderDash: [3, 3],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }, {
                        label: 'Peak (Kbps)',
                        data: sampled.map(b => b.peak),
                        borderColor: '#c4b5fd',
                        borderDash: [2, 2],
                        fill: false,
                        tension: 0.4,
                        pointRadius: 0
                    }]
                },
                options: getChartOptions()
            });
        }
    }

    // Network State Summary (Doughnut)
    const netTotal = results.networkStateTotal;
    if (netTotal.normal + netTotal.overuse + netTotal.underuse > 0) {
        const canvas = document.getElementById('networkSummaryChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            charts.networkSummary = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Normal', 'Overuse', 'Underuse'],
                    datasets: [{
                        data: [netTotal.normal, netTotal.overuse, netTotal.underuse],
                        backgroundColor: ['#10b981', '#ef4444', '#f59e0b']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#a0a0b0' } }
                    }
                }
            });
        }
    }
}

function getChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#a0a0b0' }
            },
            zoom: {
                pan: {
                    enabled: true,
                    mode: 'x',
                    modifierKey: 'shift' // Hold Shift to pan
                },
                zoom: {
                    wheel: {
                        enabled: true,
                        modifierKey: 'ctrl' // Ctrl + wheel to zoom
                    },
                    drag: {
                        enabled: true,
                        backgroundColor: 'rgba(59, 130, 246, 0.2)',
                        borderColor: 'rgba(59, 130, 246, 0.8)',
                        borderWidth: 1
                    },
                    mode: 'x'
                }
            }
        },
        scales: {
            x: {
                display: true,
                ticks: { color: '#6a6a7a', maxTicksLimit: 10 },
                grid: { color: 'rgba(255,255,255,0.05)' }
            },
            y: {
                display: true,
                ticks: { color: '#6a6a7a' },
                grid: { color: 'rgba(255,255,255,0.05)' }
            }
        }
    };
}

// ===== Timeline Rendering =====
function renderTimeline(issues) {
    const timelineList = document.getElementById('timelineList');

    if (issues.length === 0) {
        timelineList.innerHTML = '<p style="color: #10b981; text-align: center; padding: 2rem;">✅ 감지된 이슈가 없습니다!</p>';
        return;
    }

    // Sort by timestamp (newest first)
    const sortedIssues = [...issues].sort((a, b) =>
        b.timestamp.localeCompare(a.timestamp)
    );

    // Limit to 100 most recent issues
    const displayIssues = sortedIssues.slice(0, 100);

    timelineList.innerHTML = displayIssues.map(issue => `
        <div class="timeline-item ${issue.type}">
            <div class="timeline-time">${issue.timestamp}</div>
            <div class="timeline-content">
                <span class="timeline-type ${issue.type}">${issue.type.toUpperCase()}</span>
                <span class="timeline-category">[${issue.category}]</span>
                <p class="timeline-message">${issue.message}</p>
            </div>
        </div>
    `).join('');
}

// Make removeFile globally accessible
window.removeFile = removeFile;

// Reset zoom for specific chart
function resetZoom(chartName) {
    if (charts[chartName]) {
        charts[chartName].resetZoom();
    }
}
window.resetZoom = resetZoom;
