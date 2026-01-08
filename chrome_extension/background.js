// background.js - Listens for downloads, PAUSES, scans, and Resumes/Cancels

chrome.downloads.onCreated.addListener((downloadItem) => {
    console.log("Download started:", downloadItem.url);

    // 1. IMMEDIATE PAUSE to prevent file from finishing while we scan
    chrome.downloads.pause(downloadItem.id, () => {
        if (chrome.runtime.lastError) {
            console.warn("Pause failed (Download might have finished/cancelled):", chrome.runtime.lastError.message);
            return;
        }

        console.log("Download paused for scanning...");

        // Helper to extract filename from URL if API returns empty
        let finalFilename = downloadItem.filename;
        if (!finalFilename || finalFilename === "") {
            try {
                finalFilename = downloadItem.url.substring(downloadItem.url.lastIndexOf('/') + 1).split('?')[0];
                if (!finalFilename) finalFilename = "downloaded_file.dat";
            } catch (e) {
                finalFilename = "unknown_file";
            }
        }

        // 2. Fetch content
        fetch(downloadItem.url)
            .then(response => response.text())
            .then(content => {
                return fetch('http://localhost:8000/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: downloadItem.url,
                        filename: finalFilename,
                        content: content,
                        type: "download_deep_scan"
                    })
                });
            })
            .then(response => response.json())
            .then(data => {
                if (data.verdict === "DANGEROUS" || data.verdict === "MALWARE") {
                    // 3. THREAT FOUND -> KEEP PAUSED & WARN
                    console.log("Download PAUSED due to threat.");

                    // Visual Notification
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'icon48.png',
                        title: '🚫 MEDI-GUARD: THREAT BLOCKED',
                        message: `MALWARE DETECTED: ${downloadItem.filename}\n\nThis file has NOT been saved to the Hospital Vault.\nIt violates security protocols.`,
                        priority: 2,
                        requireInteraction: true
                    });

                    chrome.action.setBadgeText({ text: "!" });
                    chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });

                    // We leave it PAUSED. The user must actively override in chrome://downloads if they really want it.
                } else {
                    // 4. SAFE -> RESUME
                    console.log("Scan Passed. Resuming download.");

                    // SUCCESS NOTIFICATION
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'icon48.png',
                        title: '✅ MEDI-GUARD: FILE SECURED',
                        message: `File: ${downloadItem.filename}\n\nStatus: CLEAN\nAction: Encrypted & Saved to Vault.\nID: ${data.vault_name || "N/A"}`,
                        priority: 1
                    });

                    chrome.downloads.resume(downloadItem.id, () => {
                        if (chrome.runtime.lastError) console.warn("Resume failed:", chrome.runtime.lastError.message);
                    });
                }
            })
            .catch(error => {
                console.error("Scan failed/Timeout:", error);
                // Fallback: Resume if scan fails (Fail Open)
                chrome.downloads.resume(downloadItem.id, () => {
                    if (chrome.runtime.lastError) console.warn("Resume failed during fallback:", chrome.runtime.lastError.message);
                });
            });
    });
});
