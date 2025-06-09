# 🔍 Smart Nmap Plus – Advanced Nmap GUI Tool

Smart Nmap Plus is a powerful, Zenmap-style graphical interface built with Python and Tkinter to streamline `nmap` scanning. Designed for penetration testers, cybersecurity learners, and sysadmins, this tool makes it easier to configure scans, see results in real-time, and customize commands—all from an intuitive dark-mode UI.

---

## 🚀 Features

- 🎨 Stylish, readable dark theme UI
- 🧠 Real-time command preview
- 💬 Live output display (auto-scroll enabled)
- 🧪 Choose from multiple scan types: SYN, TCP, UDP, NULL, etc.
- 🧾 Support for NSE scripts and custom script paths
- ⚙️ Optional OS and version detection
- 🚀 Multi-threaded scans – UI stays responsive
- 🖱️ Hover effects for better UX

---

## 🛠️ How to Use

1. **Enter Target IP or Hostname**  
   Example: `scanme.nmap.org` or your local IP (`192.168.1.1`)

2. **Set Port Range** *(optional)*  
   Example: `1-65535`, `80,443,8080`  
   Leave blank for default behavior.

3. **Choose Scan Type**  
   Select from drop-down:
   - SYN Scan (`-sS`)
   - TCP Connect Scan (`-sT`)
   - UDP Scan (`-sU`)
   - NULL, FIN, XMAS scans, or Ping scan

4. **Enable/Disable Additional Options**  
   - ✅ Version Detection (`-sV`)
   - ✅ OS Detection (`-O`)
   - ✅ Timing (`-T0` to `-T5`)

5. **Use NSE Scripts (Optional)**  
   - Enter a script name or category: `vuln`, `http-*`, `ftp-*`, etc.
   - Or browse for a custom script `.nse` file

6. **View Nmap Command Preview**  
   - Real-time command line preview updates as you change fields

7. **Run the Scan**  
   - Press the `Run Scan` button  
   - Output appears live below

8. **Analyze Results**  
   - Scroll through the scan log  
   - Copy results as needed for documentation or reporting

---

## 🖼️ Screenshots

> *Coming soon — add your screenshots here*

---

## 🧱 Project Structure
smart-nmap-plus/
├── advanced_nmap_gui.py # Main GUI script
├── README.md # Project documentation
├── requirements.txt # Python dependencies
├── .gitignore # Git ignore rules




---

## ⚙️ Setup Instructions

> Recommended: Use Python 3.10+  
> Required: `nmap` must be installed and available in your system PATH

### 🔄 Step-by-step Setup with Virtual Environment

```bash
# 1. Clone the repository
git clone https://github.com/your-username/smart-nmap-plus.git
cd smart-nmap-plus

# 2. (Optional but recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# 3. Install required Python packages
pip install -r requirements.txt



📦 requirements.txt

tk

If using a minimal Linux distro (like Kali Lite), you might also need to install:

sudo apt install python3-tk nmap







