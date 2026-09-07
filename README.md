# SecureMailScope v0.1

The first blueprint milestone: real PCAP -> TShark packet evidence -> canonical session JSON -> Streamlit analyst view.

Start the TShark API:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn api:app --reload
```

Then start the Next.js frontend in another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

TShark is found from PATH or `C:\Program Files\Wireshark\tshark.exe`.

## Zeek phase

Start Docker Desktop, then the optional Zeek worker can run `zeek/zeek:latest` against the same PCAPs and emit JSON `conn`, `ssl`, `x509`, and protocol logs for evidence fusion.
