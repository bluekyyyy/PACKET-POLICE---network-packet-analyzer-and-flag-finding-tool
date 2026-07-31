# Features

- Analyze **PCAP** and **PCAPNG** network capture files through a web interface
- Interactive packet inspection with detailed protocol information
- Displays source, destination, protocol, timestamps, and packet metadata
- Supports custom display filters for targeted packet analysis
- View decoded protocol fields and raw packet data
- Fast backend powered by FastAPI and PyShark
- Automatic reconstruction of fragmented network data
- Built-in CTF flag discovery engine
- Combines jumbled or fragmented flag pieces spread across multiple packets
- Detects flags hidden in multiple encoding formats
- Reassembles Base64 fragments before decoding
- Searches reconstructed streams for hidden flags
- Supports analysis of large network captures
- Responsive web dashboard for network traffic analysis

---

# CTF Flag Detection

The application includes an integrated CTF forensic engine that searches uploaded network captures for hidden flags.

It can detect flags from:

- Plain text
- Base64
- Base32
- Hexadecimal
- URL encoding
- ROT13
- Atbash cipher
- Reconstructed payload streams
- Stitched Base64 `data=` fragments
- Fragmented or jumbled packet payloads

Instead of inspecting packets independently, the analyzer reconstructs fragmented application data and searches the combined stream, allowing it to recover flags that are split across multiple packets.

This makes it particularly useful for **network forensics**, **packet analysis**, and **Capture The Flag (CTF)** challenges.

---

![](https://github.com/user-attachments/assets/7a2acf0f-3d72-4cfb-b64f-10e9c5737b4b)

![](https://github.com/user-attachments/assets/68b099fa-123f-4bf3-8a5d-807be017ada5)

![](https://github.com/user-attachments/assets/b362670c-43d4-4386-8c49-6e7413f4dd4b)

![](https://github.com/user-attachments/assets/3bebb926-f6b4-4e54-a4af-4cb5229d0452)

![](https://github.com/user-attachments/assets/d41ad40d-55a6-4b04-9531-a0aa312e32a7)

---
