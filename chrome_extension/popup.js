document.getElementById('scan-btn').addEventListener('click', async () => {
    const statusDiv = document.getElementById('result');
    statusDiv.innerHTML = "📡 Contacting Security Hub...";

    // Get current tab URL
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
        statusDiv.innerHTML = "❌ Error: No active tab.";
        return;
    }

    document.getElementById('current-url').textContent = tab.url.substring(0, 40) + "...";

    try {
        const response = await fetch('http://localhost:8000/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: tab.url })
        });

        if (!response.ok) {
            throw new Error('API Bridge Offline');
        }

        const data = await response.json();

        if (data.verdict === "SAFE") {
            statusDiv.innerHTML = `<span class="safe">✅ VERDICT: SAFE</span><br>Risk Score: ${data.risk_score}`;
        } else {
            statusDiv.innerHTML = `<span class="danger">⚠️ VERDICT: ${data.verdict}</span><br>Threats: ${data.threats.join(', ')}`;
        }

    } catch (error) {
        statusDiv.innerHTML = "❌ Connection Failed. Is 'utils/api_bridge.py' running?";
    }
});
