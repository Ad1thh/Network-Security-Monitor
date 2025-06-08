// Dashboard update functions
let charts = {};
let lastUpdate = Date.now();
const updateInterval = 1000; // 1 second

// Initialize interface selection
let availableInterfaces = [];
let currentInterface = null;

// Initialize charts
function initializeCharts() {
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 0
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                }
            },
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                }
            }
        }
    };

    // Network Traffic Chart
    charts.traffic = new Chart(document.getElementById('trafficChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Upload (MB/s)',
                    data: [],
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    fill: true
                },
                {
                    label: 'Download (MB/s)',
                    data: [],
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    fill: true
                }
            ]
        },
        options: {
            ...chartDefaults,
            plugins: {
                legend: {
                    position: 'top',
                    align: 'start'
                }
            }
        }
    });

    // Threat Detection Chart
    charts.threats = new Chart(document.getElementById('threatChart').getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Anomalies', 'Port Scans', 'DDoS', 'Data Exfil', 'High Traffic'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(255, 159, 64, 0.5)',
                    'rgba(255, 205, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(54, 162, 235, 0.5)'
                ],
                borderColor: [
                    'rgb(255, 99, 132)',
                    'rgb(255, 159, 64)',
                    'rgb(255, 205, 86)',
                    'rgb(75, 192, 192)',
                    'rgb(54, 162, 235)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            ...chartDefaults,
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });

    // Traffic Classification Chart
    charts.classification = new Chart(document.getElementById('classificationChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Upload', 'Download', 'Interactive', 'Mixed', 'Idle'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(153, 102, 255, 0.5)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    align: 'center'
                }
            }
        }
    });

    // Handle window resize
    window.addEventListener('resize', debounce(() => {
        Object.values(charts).forEach(chart => {
            if (chart && chart.resize) {
                chart.resize();
            }
        });
    }, 250));
}

// Debounce function to limit resize events
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Update dashboard with new data
function updateDashboard(data) {
    if (!data) return;
    
    const timestamp = new Date().toLocaleTimeString();
    
    // Update system statistics
    if (data.system) {
        document.getElementById('cpuUsage').textContent = data.system.cpu_percent.toFixed(1);
        document.getElementById('memoryUsage').textContent = data.system.memory_percent.toFixed(1);
        document.getElementById('activeConnections').textContent = data.system.connections_established;
    }
    
    // Update network statistics
    if (data.network) {
        const networkData = Object.values(data.network)[0];
        if (networkData) {
            // Update interface info
            const interfaceElement = document.getElementById('networkInterface');
            interfaceElement.innerHTML = `
                <i class="fas ${networkData.interface_type === 'Wireless' ? 'fa-wifi' : 'fa-ethernet'}"></i>
                Interface: ${networkData.interface}
                <span class="status-badge ${networkData.status === 'up' ? 'active' : 'inactive'}">
                    ${networkData.status === 'up' ? 'Active' : 'Inactive'}
                </span>
            `;
            
            // Update traffic rates
            document.getElementById('bytesSent').textContent = formatBytes(networkData.bytes_sent_rate) + '/s';
            document.getElementById('bytesReceived').textContent = formatBytes(networkData.bytes_recv_rate) + '/s';
            document.getElementById('packetsRate').textContent = Math.round(networkData.packets_sent_rate + networkData.packets_recv_rate);
            
            // Update traffic chart
            updateTrafficChart(timestamp, networkData);
        }
    }
    
    // Update threat information
    if (data.threats) {
        updateThreatInfo(data.threats);
    }
    
    // Update traffic classification
    if (data.classifications) {
        updateTrafficClassification(data.classifications);
    }
    
    // Update active connections table
    if (data.connections) {
        updateConnectionsTable(data.connections);
    }
    
    // Update remarks
    updateRemarks(data);
    
    lastUpdate = Date.now();
}

// Helper function to format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Update traffic chart
function updateTrafficChart(timestamp, networkData) {
    const uploadMBps = networkData.bytes_sent_rate / (1024 * 1024);
    const downloadMBps = networkData.bytes_recv_rate / (1024 * 1024);
    
    charts.traffic.data.labels.push(timestamp);
    charts.traffic.data.datasets[0].data.push(uploadMBps);
    charts.traffic.data.datasets[1].data.push(downloadMBps);
    
    // Keep last 60 data points (1 minute)
    if (charts.traffic.data.labels.length > 60) {
        charts.traffic.data.labels.shift();
        charts.traffic.data.datasets.forEach(dataset => dataset.data.shift());
    }
    
    charts.traffic.update();
}

// Update threat information
function updateThreatInfo(threats) {
    // Update threat chart
    const threatCounts = [
        threats.anomalies.length,
        threats.port_scans.length,
        threats.ddos.length,
        threats.data_exfiltration.length,
        threats.high_traffic.length
    ];
    
    charts.threats.data.datasets[0].data = threatCounts;
    charts.threats.update();
    
    // Update threat list
    const threatList = document.getElementById('threatList');
    threatList.innerHTML = '';
    
    Object.entries(threats).forEach(([type, items]) => {
        items.forEach(threat => {
            if (threat.timestamp) {
                const threatTime = new Date(threat.timestamp);
                if (Date.now() - threatTime.getTime() < 300000) { // Show threats from last 5 minutes
                    const li = document.createElement('li');
                    li.className = `threat-item ${threat.severity}`;
                    li.innerHTML = `
                        <span class="threat-type">${type}</span>
                        <span class="threat-severity">${threat.severity}</span>
                        <span class="threat-time">${threatTime.toLocaleTimeString()}</span>
                        <span class="threat-details">${threat.details}</span>
                    `;
                    threatList.appendChild(li);
                }
            }
        });
    });
}

// Update traffic classification
function updateTrafficClassification(classifications) {
    const types = ['upload', 'download', 'interactive', 'mixed', 'idle'];
    const counts = types.map(type => classifications.counts[type] || 0);
    
    charts.classification.data.datasets[0].data = counts;
    charts.classification.update();
}

// Update connections table
function updateConnectionsTable(connections) {
    const table = document.getElementById('connectionsTable');
    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';
    
    connections.slice(0, 10).forEach(conn => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${conn.local_address}:${conn.local_port}</td>
            <td>${conn.remote_address}:${conn.remote_port}</td>
            <td>${conn.status}</td>
        `;
        tbody.appendChild(row);
    });
}

// Update remarks section
function updateRemarks(data) {
    const remarks = [];
    
    if (data.network) {
        const networkData = Object.values(data.network)[0];
        if (networkData) {
            // Check connection status
            if (networkData.status !== 'up') {
                remarks.push('Network interface is down');
            }
            
            // Check error rate
            const totalPackets = networkData.packets_sent_rate + networkData.packets_recv_rate;
            if (totalPackets > 0) {
                const errorRate = (networkData.errors || 0) / totalPackets;
                if (errorRate > 0.01) {
                    remarks.push(`High error rate detected: ${(errorRate * 100).toFixed(2)}%`);
                }
            }
            
            // Check packet loss
            if (networkData.packet_loss > 0.05) {
                remarks.push(`High packet loss detected: ${(networkData.packet_loss * 100).toFixed(2)}%`);
            }
            
            // Check latency
            if (networkData.latency > 100) {
                remarks.push(`High latency detected: ${networkData.latency.toFixed(0)}ms`);
            }
        }
    }
    
    // Update remarks display
    const remarksElement = document.getElementById('remarks');
    if (remarks.length > 0) {
        remarksElement.innerHTML = remarks.join('<br>');
    } else {
        remarksElement.textContent = 'No issues detected';
    }
}

// Initialize interface selection
function initializeInterfaceSelection() {
    const changeInterfaceBtn = document.getElementById('changeInterface');
    const interfaceList = document.getElementById('interfaceList');
    
    // Load available interfaces
    fetch('/interfaces')
        .then(response => response.json())
        .then(interfaces => {
            availableInterfaces = interfaces;
            if (interfaces.length > 0) {
                currentInterface = interfaces.find(iface => iface.status === 'up') || interfaces[0];
                updateInterfaceDisplay(currentInterface);
            }
        })
        .catch(error => console.error('Error loading interfaces:', error));
    
    // Toggle interface list
    changeInterfaceBtn.addEventListener('click', () => {
        if (interfaceList.style.display === 'none') {
            // Show interface list
            interfaceList.style.display = 'block';
            updateInterfaceList();
        } else {
            interfaceList.style.display = 'none';
        }
    });
    
    // Close interface list when clicking outside
    document.addEventListener('click', (event) => {
        if (!event.target.closest('.interface-selector') && 
            !event.target.closest('.interface-list')) {
            interfaceList.style.display = 'none';
        }
    });
}

function updateInterfaceList() {
    const interfaceList = document.getElementById('interfaceList');
    interfaceList.innerHTML = '';
    
    availableInterfaces.forEach(iface => {
        const option = document.createElement('div');
        option.className = `interface-option ${iface.name === currentInterface.name ? 'selected' : ''}`;
        option.innerHTML = `
            <i class="fas ${iface.type === 'Wireless' ? 'fa-wifi' : 'fa-ethernet'}"></i>
            <div class="interface-details">
                <div class="interface-name">${iface.name}</div>
                <div class="interface-info">
                    ${iface.type} | ${iface.addresses.join(', ') || 'No IP'}
                    ${iface.speed ? ` | ${iface.speed} Mbps` : ''}
                </div>
            </div>
            <span class="interface-status ${iface.status}">${iface.status}</span>
        `;
        
        option.addEventListener('click', () => {
            if (iface.name !== currentInterface.name) {
                changeInterface(iface);
            }
        });
        
        interfaceList.appendChild(option);
    });
}

function changeInterface(newInterface) {
    fetch(`/interface/${newInterface.name}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            currentInterface = newInterface;
            updateInterfaceDisplay(newInterface);
            document.getElementById('interfaceList').style.display = 'none';
        }
    })
    .catch(error => console.error('Error changing interface:', error));
}

function updateInterfaceDisplay(iface) {
    const interfaceElement = document.getElementById('networkInterface');
    interfaceElement.innerHTML = `
        <i class="fas ${iface.type === 'Wireless' ? 'fa-wifi' : 'fa-ethernet'}"></i>
        Interface: ${iface.name}
        <span class="status-badge ${iface.status === 'up' ? 'active' : 'inactive'}">
            ${iface.status === 'up' ? 'Active' : 'Inactive'}
        </span>
    `;
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeInterfaceSelection();
    
    // Start periodic updates
    function fetchUpdates() {
        fetch('/stats')
            .then(response => response.json())
            .then(data => updateDashboard(data))
            .catch(error => console.error('Error fetching updates:', error));
    }
    
    // Initial update
    fetchUpdates();
    
    // Set up periodic updates
    setInterval(fetchUpdates, updateInterval);
}); 