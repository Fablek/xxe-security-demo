# XXE Security Demo

🎓 Educational demonstration of XML External Entity (XXE) injection vulnerabilities

## 📖 About

This project demonstrates XXE vulnerabilities in web applications and secure coding practices for the **Web and Mobile Application Security Testing** course at Silesian University of Technology.

## 🎯 Project Goals

- Demonstrate how XXE attacks work
- Show different types of XXE exploitation (File Disclosure, SSRF, DoS)
- Implement secure XML parsing practices
- Provide educational materials and documentation

## 📁 Project Structure
```
xxe-security-demo/
├── vulnerable_app/     # Flask app with XXE vulnerabilities
│   ├── templates/      # HTML templates
│   └── uploads/        # XML file uploads
├── secure_app/         # Secure version with XXE prevention
│   └── templates/      # HTML templates
├── exploits/           # Python scripts demonstrating attacks
│   ├── file_disclosure.py
│   ├── ssrf_attack.py
│   └── dos_attack.py
├── docs/               # Documentation and screenshots
└── requirements.txt    # Python dependencies
```

## 🛠️ Technology Stack

- **Python 3.11+**
- **Flask** - Web framework
- **lxml** - XML parser (vulnerable configuration)
- **defusedxml** - Secure XML parser
- **Burp Suite Community** - Security testing tool

## 🚀 Installation & Setup

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)
- Burp Suite Community Edition (optional)

### Installation Steps
```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/xxe-security-demo.git
cd xxe-security-demo

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# 4. Install dependencies
pip install -r requirements.txt
```

## 🧪 Usage

### Running Vulnerable Application
```bash
cd vulnerable_app
python app.py
# Visit: http://localhost:5000
```

### Running Secure Application
```bash
cd secure_app
python app.py
# Visit: http://localhost:5000
```

### Running Exploits
```bash
cd exploits
python file_disclosure.py
```

## 📚 XXE Attack Types Demonstrated

1. **Local File Disclosure** - Reading sensitive files from server
2. **SSRF (Server-Side Request Forgery)** - Making requests to internal systems
3. **Denial of Service (Billion Laughs)** - Resource exhaustion attack

## ⚠️ Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This project is designed for learning about web security vulnerabilities. Do not use these techniques against systems you don't have explicit permission to test. Unauthorized access to computer systems is illegal.

## 📖 Learning Resources

- [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger XXE Tutorial](https://portswigger.net/web-security/xxe)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- 
## 📝 License

MIT License - Educational use only

---

**⭐ If you find this project helpful, please give it a star!**