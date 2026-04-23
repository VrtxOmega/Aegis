const initSystemStatus = (aegis) => {
    const updateSystemStatus = async () => {
        const status = await aegis.getSystemStatus();
        if (status.error) {
            console.error('System Status Error:', status.error);
            document.getElementById('system-status-content').innerHTML = `<p class="error-message">Error: ${status.error}</p>`;
            return;
        }

        document.getElementById('cpu-usage').innerText = `${status.cpu_percent}%`;
        document.getElementById('cpu-progress').style.width = `${status.cpu_percent}%`;

        document.getElementById('ram-usage').innerText = `${status.ram_percent}% (${status.ram_used_gb}GB / ${status.ram_total_gb}GB)`;
        document.getElementById('ram-progress').style.width = `${status.ram_percent}%`;

        document.getElementById('disk-usage').innerText = `${status.disk_percent}% (${status.disk_used_gb}GB / ${status.disk_total_gb}GB)`;
        document.getElementById('disk-progress').style.width = `${status.disk_percent}%`;

        const gpu = status.gpu;
        document.getElementById('gpu-name').innerText = gpu.name !== 'N/A' ? gpu.name : 'No GPU Detected';
        document.getElementById('gpu-util').innerText = gpu.utilization !== 'N/A' ? `${gpu.utilization}%` : '--%';
        document.getElementById('gpu-progress').style.width = gpu.utilization !== 'N/A' ? `${gpu.utilization}%` : '0%';
        document.getElementById('gpu-mem').innerText = gpu.memory_used !== 'N/A' ? `${gpu.memory_used}MB / ${gpu.memory_total}MB` : '--MB / --MB';
        document.getElementById('gpu-temp').innerText = gpu.temperature !== 'N/A' ? `${gpu.temperature}°C` : '--°C';
        document.getElementById('gpu-power').innerText = gpu.power_draw !== 'N/A' ? `${gpu.power_draw}W` : '--W';
    };

    updateSystemStatus();
    setInterval(updateSystemStatus, 5000); // Refresh every 5 seconds
};
