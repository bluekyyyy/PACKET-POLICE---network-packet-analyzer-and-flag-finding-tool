# Network Packet Analyzer Dashboard

A web-based **Network Packet Analyzer Dashboard** built with **FastAPI**, **PyShark**, and a modern HTML frontend. This application captures and analyzes network packets in real time, displaying protocol statistics, packet details, and live traffic visualizations.

---

## Features

- 📡 Live network packet capture
- 📊 Real-time protocol distribution
- 📈 Traffic visualization dashboard
- 🔍 Detailed packet inspection
- ⚡ FastAPI backend
- 🎨 Responsive web interface

---

## Tech Stack

- **Backend:** FastAPI
- **Packet Capture:** PyShark (TShark)
- **Frontend:** HTML, CSS, JavaScript
- **Server:** Uvicorn

---

## Project Structure

```text
.
├── backend/
│   ├── main.py
│   ├── ...
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   ├── script.js
│
├── screenshots/
└── README.md
```

---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/<your-repository>.git

cd <your-repository>
```

---

## 2. Install Python Virtual Environment

```bash
sudo apt update

sudo apt install python3-venv python3-full
```

---

## 3. Create Virtual Environment

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

---

## 4. Install Python Dependencies

```bash
pip install fastapi uvicorn pyshark python-multipart
```

---

## 5. Install TShark

PyShark depends on **TShark**.

```bash
sudo apt update

sudo apt install tshark
```

Verify installation:

```bash
tshark --version
```

---

# Running the Application

## Option 1

Run from the project root:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Option 2

If your FastAPI app is inside the `backend` folder:

```bash
cd backend

uvicorn main:app --reload
```

---

## Open the Frontend

Simply open

```text
index.html
```

in your preferred web browser.

---

# Screenshots


![Dashboard](https://github.com/user-attachments/assets/7a2acf0f-3d72-4cfb-b64f-10e9c5737b4b)

---


![Live Packet Capture](https://github.com/user-attachments/assets/68b099fa-123f-4bf3-8a5d-807be017ada5)

---

![Protocol Statistics](https://github.com/user-attachments/assets/b362670c-43d4-4386-8c49-6e7413f4dd4b)

---


![Packet Details](https://github.com/user-attachments/assets/3bebb926-f6b4-4e54-a4af-4cb5229d0452)

---


![Traffic Analysis](https://github.com/user-attachments/assets/d41ad40d-55a6-4b04-9531-a0aa312e32a7)

---

# Requirements

- Python 3.9+
- FastAPI
- Uvicorn
- PyShark
- TShark
- Modern Web Browser

---

# Notes

- Root or sudo permissions may be required for packet capturing.
- Ensure TShark is correctly installed before running the application.
- Firewall or OS permissions may affect packet capture functionality.

---

# Future Improvements

- Export captured packets
- PCAP file upload support
- Advanced filtering
- User authentication
- Dark mode
- Historical traffic analytics

---

# License

This project is licensed under the MIT License.

---
