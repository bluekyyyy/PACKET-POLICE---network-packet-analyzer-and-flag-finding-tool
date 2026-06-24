// --- DYNAMIC COLOR ENGINE ---
const defaultColors = {
    tcp: "#a5b4fc", udp: "#93c5fd", http: "#86efac", dns: "#67e8f9",
    icmp: "#f0abfc", arp: "#fde047", tls: "#d8b4fe", default: "#ffffff"
};

let protocolColors = JSON.parse(localStorage.getItem('packetColors')) || {...defaultColors};

function hexToRgba(hex, alpha) {
    let r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function getRandomColor() {
    return '#' + Math.floor(Math.random()*16777215).toString(16).padStart(6, '0');
}
// -----------------------------

const pcapInput = document.getElementById('pcapInput');
const folderInput = document.getElementById('folderInput');
const targetDisplay = document.getElementById('targetDisplay');

document.getElementById('selectFileBtn').addEventListener('click', () => pcapInput.click());
document.getElementById('selectFolderBtn').addEventListener('click', () => folderInput.click());

pcapInput.addEventListener('change', (e) => {
    if(e.target.files.length > 0) targetDisplay.innerHTML = `<i class="fa-solid fa-file"></i> ${e.target.files[0].name}`;
});

folderInput.addEventListener('change', (e) => {
    if(e.target.files.length > 0) targetDisplay.innerHTML = `<i class="fa-solid fa-folder"></i> Selected ${e.target.files.length} files`;
});

// Quick Filters
document.querySelectorAll('.filter-tag').forEach(tag => {
    tag.addEventListener('click', (e) => {
        const filterVal = e.target.getAttribute('data-filter');
        const filterInput = document.getElementById('filterInput');
        filterInput.value = filterVal;
        filterInput.focus();
    });
});

const modal = document.getElementById('manualModal');
document.getElementById('helpBtn').addEventListener('click', () => modal.classList.add('show'));
document.getElementById('closeModal').addEventListener('click', () => modal.classList.remove('show'));

document.getElementById('uploadBtn').addEventListener('click', async () => {
    if (!pcapInput.files[0]) return alert("Please select a PCAP file first.");

    const filterInput = document.getElementById('filterInput').value;
    const apiKeyInput = document.getElementById('apiKeyInput').value;
    const tbody = document.getElementById('packetBody');
    
    const formData = new FormData();
    formData.append("file", pcapInput.files[0]);
    formData.append("display_filter", filterInput); 
    formData.append("api_key", apiKeyInput);

    tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'><i class='fa-solid fa-spinner fa-spin'></i> Analyzing Traffic...</td></tr>";

    try {
        const response = await fetch("http://127.0.0.1:8000/api/upload", {
            method: "POST",
            body: formData
        });
        
        if (!response.ok) throw new Error(`Server Error: ${response.statusText}`);
        
        const data = await response.json();
        populateTable(data.packets);
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan='5' style='text-align:center; color: #ff4a4a;'><i class='fa-solid fa-triangle-exclamation'></i> Analysis Failed: ${error.message}</td></tr>`;
    }
});

document.getElementById('flagBtn').addEventListener('click', async () => {
    if (!pcapInput.files[0]) return alert("Please select a PCAP file first.");

    const filterInput = document.getElementById('filterInput').value;
    const apiKeyInput = document.getElementById('apiKeyInput').value;
    const flagList = document.getElementById('flagList');

    const formData = new FormData();
    formData.append("file", pcapInput.files[0]);
    formData.append("display_filter", filterInput); 
    formData.append("api_key", apiKeyInput);

    flagList.innerHTML = "<li style='color: var(--text-main);'><i class='fa-solid fa-spinner fa-spin'></i> Extracting encryptions...</li>";

    try {
        const response = await fetch("http://127.0.0.1:8000/api/find_flags", {
            method: "POST",
            body: formData
        });
        
        if (!response.ok) throw new Error(`Server Error`);
        
        const data = await response.json();
        flagList.innerHTML = "";
        
        if(!data.flags || data.flags.length === 0) {
            flagList.innerHTML = "<li style='color: var(--text-main);'><i class='fa-solid fa-circle-xmark'></i> No flags found in current view.</li>";
        } else {
            data.flags.forEach(flag => {
                let li = document.createElement("li");
                li.style.color = "#00ff41"; 
                li.innerHTML = `<i class="fa-solid fa-check"></i> ${flag}`;
                flagList.appendChild(li);
            });
        }
    } catch (error) {
        flagList.innerHTML = `<li style='color: #ff4a4a;'><i class='fa-solid fa-triangle-exclamation'></i> Error finding flags.</li>`;
    }
});

function formatHexDump(hexStr) {
    if(!hexStr) return "No raw bytes available for this packet.";
    
    let hexOutput = "=== RAW HEX ===\n";
    let asciiOutput = "\n=== ASCII DECODED ===\n";
    
    for(let i = 0; i < hexStr.length; i += 32) {
        let chunk = hexStr.slice(i, i + 32);
        let offset = (i / 2).toString(16).padStart(4, '0');
        
        let hexFormatted = "";
        let ascii = "";
        
        if (chunk.length > 0) {
            let pairs = chunk.match(/.{1,2}/g);
            for(let j = 0; j < pairs.length; j++) {
                hexFormatted += pairs[j] + " ";
                if (j === 7) hexFormatted += " "; 
                
                let c = parseInt(pairs[j], 16);
                ascii += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
            }
        }
        
        hexOutput += `[${offset}]  ${hexFormatted}\n`;
        asciiOutput += `[${offset}]  ${ascii}\n`;
    }
    
    return hexOutput + asciiOutput;
}

function populateTable(packets) {
    const tbody = document.getElementById('packetBody');
    tbody.innerHTML = "";
    
    if (!packets || packets.length === 0) {
        tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>No packets found.</td></tr>";
        return;
    }
    
    const layerIcons = {
        'ETH': 'fa-network-wired',
        'IP': 'fa-globe',
        'IPV6': 'fa-globe',
        'TCP': 'fa-exchange-alt',
        'UDP': 'fa-paper-plane',
        'HTTP': 'fa-file-code',
        'DNS': 'fa-address-book'
    };
    
    const ansiRegex = /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;

    packets.forEach(pkt => {
        let tr = document.createElement("tr");
        
        // --- DYNAMIC COLOR ASSIGNMENT ---
        let safeProto = (pkt.protocol || "unknown").toLowerCase();
        
        if (!protocolColors[safeProto]) {
            protocolColors[safeProto] = getRandomColor();
            localStorage.setItem('packetColors', JSON.stringify(protocolColors));
        }

        let pColor = protocolColors[safeProto];
        tr.style.backgroundColor = hexToRgba(pColor, 0.15);
        tr.style.color = pColor;
        tr.setAttribute('data-proto', safeProto);
        // --------------------------------

        tr.innerHTML = `
            <td>${pkt.no}</td>
            <td>${pkt.source}</td>
            <td>${pkt.destination}</td>
            <td>${pkt.protocol}</td>
            <td>${pkt.info}</td>
        `;
        
        tr.addEventListener('click', () => {
            document.querySelectorAll('#packetBody tr').forEach(row => row.classList.remove('selected-row'));
            tr.classList.add('selected-row');
            
            const detailsView = document.getElementById('detailsView');
            detailsView.innerHTML = ''; 
            
            if (pkt.details) {
                pkt.details.forEach(layer => {
                    const detailsEl = document.createElement('details');
                    detailsEl.open = true; 
                    
                    const summaryEl = document.createElement('summary');
                    summaryEl.className = 'layer-header';
                    const iconClass = layerIcons[layer.name] || 'fa-cube';
                    summaryEl.innerHTML = `<i class="fa-solid ${iconClass}"></i> ${layer.name} Layer`;
                    detailsEl.appendChild(summaryEl);
                    
                    const ul = document.createElement('ul');
                    
                    layer.fields.forEach(f => {
                        let rawKey = "";
                        let rawVal = "";

                        if (typeof f === 'string') {
                            const splitIndex = f.indexOf(':');
                            if (splitIndex !== -1) {
                                rawKey = f.substring(0, splitIndex).trim();
                                rawVal = f.substring(splitIndex + 1).trim();
                            } else {
                                rawKey = f;
                            }
                        } else {
                            rawKey = f.key;
                            rawVal = f.val;
                        }

                        let cleanKey = rawKey.replace(ansiRegex, '').trim();
                        let cleanVal = rawVal.replace(ansiRegex, '').trim();

                        if (cleanKey.toLowerCase().includes('_raw') || 
                            cleanKey.toLowerCase().includes('_tree') || 
                            cleanKey.toLowerCase().includes('_resolved') || 
                            cleanKey.toLowerCase() === 'expert') {
                            return; 
                        }

                        cleanKey = cleanKey.replace(/[\._]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

                        if (cleanKey && cleanVal && cleanVal !== "None") {
                            const li = document.createElement('li');
                            li.className = 'tree-field';
                            
                            const keySpan = document.createElement('span');
                            keySpan.className = 'tree-key';
                            keySpan.textContent = cleanKey;
                            
                            const valSpan = document.createElement('span');
                            valSpan.className = 'tree-val';
                            valSpan.textContent = cleanVal;
                            
                            li.appendChild(keySpan);
                            li.appendChild(valSpan);
                            ul.appendChild(li);
                        }
                    });
                    
                    if (ul.children.length > 0) {
                        detailsEl.appendChild(ul);
                        detailsView.appendChild(detailsEl);
                    }
                });
            }

            const hexDump = document.getElementById('hexDumpContent');
            hexDump.textContent = formatHexDump(pkt.raw_hex);
        });
        
        tbody.appendChild(tr);
    });
}

// --- COLOR MODAL LOGIC ---
const colorModal = document.getElementById('colorModal');
const colorList = document.getElementById('colorList');

document.getElementById('colorBtn').addEventListener('click', () => {
    populateColorSettings();
    colorModal.classList.add('show');
});

document.getElementById('closeColorModal').addEventListener('click', () => colorModal.classList.remove('show'));
window.addEventListener('click', (e) => { 
    if (e.target == colorModal) colorModal.classList.remove('show'); 
    if (e.target == modal) modal.classList.remove('show');
});

document.getElementById('resetColorsBtn').addEventListener('click', () => {
    protocolColors = {...defaultColors};
    localStorage.setItem('packetColors', JSON.stringify(protocolColors));
    populateColorSettings();
    alert("Colors reset! Re-analyze traffic to see changes.");
});

function populateColorSettings() {
    colorList.innerHTML = '';
    
    let sortedProtos = Object.keys(protocolColors).sort();
    
    sortedProtos.forEach(proto => {
        let div = document.createElement('div');
        div.className = 'color-setting-item';
        div.innerHTML = `
            <span style="font-weight: bold; text-transform: uppercase; color: ${protocolColors[proto]};">${proto}</span>
            <input type="color" value="${protocolColors[proto]}" data-proto="${proto}">
        `;
        colorList.appendChild(div);
    });

    colorList.querySelectorAll('input[type="color"]').forEach(input => {
        input.addEventListener('input', (e) => {
            let proto = e.target.getAttribute('data-proto');
            let newColor = e.target.value;
            
            protocolColors[proto] = newColor;
            localStorage.setItem('packetColors', JSON.stringify(protocolColors));
            
            e.target.previousElementSibling.style.color = newColor;
            
            document.querySelectorAll(`#packetBody tr[data-proto="${proto}"]`).forEach(row => {
                if (!row.classList.contains('selected-row')) {
                    row.style.backgroundColor = hexToRgba(newColor, 0.15);
                    row.style.color = newColor;
                }
            });
        });
    });
}