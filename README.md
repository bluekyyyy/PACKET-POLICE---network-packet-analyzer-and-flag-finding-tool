--HOW TO RUN--

sudo apt update
sudo apt install python3-venv python3-full

python3 -m venv venv

source venv/bin/activate

pip install fastapi uvicorn pyshark python-multipart

sudo apt update
sudo apt install tshark

uvicorn main:app --host 0.0.0.0 --port 8000 --reload

cd backend
uvicorn main:app --reload

open index.html in ur browser

<img width="2558" height="1351" alt="image" src="https://github.com/user-attachments/assets/7a2acf0f-3d72-4cfb-b64f-10e9c5737b4b" />

<img width="2558" height="1351" alt="image" src="https://github.com/user-attachments/assets/68b099fa-123f-4bf3-8a5d-807be017ada5" />

<img width="2558" height="1351" alt="image" src="https://github.com/user-attachments/assets/b362670c-43d4-4386-8c49-6e7413f4dd4b" />

<img width="2558" height="1351" alt="image" src="https://github.com/user-attachments/assets/3bebb926-f6b4-4e54-a4af-4cb5229d0452" />

<img width="2558" height="1351" alt="image" src="https://github.com/user-attachments/assets/d41ad40d-55a6-4b04-9531-a0aa312e32a7" />
