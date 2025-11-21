# Data Security & Privacy (DSP) Lab Programs
**Student ID:** 1DS23AI405

A comprehensive collection of security-focused Python applications covering malware simulation, vulnerability analysis, phishing detection, cryptography, and data privacy techniques.

---

## 📚 Table of Contents

- [Lab 3: Email & Virus Simulation](#lab-3-email--virus-simulation)
- [Lab 4: Vulnerability Analysis Tool](#lab-4-vulnerability-analysis-tool)
- [Lab 5: Phishing URL Detector](#lab-5-phishing-url-detector)
- [Lab 7: Hash Functions & Code Obfuscation](#lab-7-hash-functions--code-obfuscation)
- [Lab 8: Digital Signatures & Authentication](#lab-8-digital-signatures--authentication)
- [Lab 9: Data Privacy & Anonymization](#lab-9-data-privacy--anonymization)
- [Setup Instructions](#setup-instructions)

---

## Lab 3: Email & Virus Simulation

### Overview
Educational tools for simulating malware behavior and email-based threats in a safe, controlled environment. No actual harm is done to files or systems.

### Components

#### 1. Email Virus Simulator (`email_virus_simulator.py`)
A comprehensive GUI application built with Tkinter for simulating email-based threats.

**Features:**
- **Email Monitoring**: Simulates monitoring incoming emails for threats
- **Document Analysis**: Scans documents for potential virus signatures
- **Virus Detection**: Identifies and logs potential threats
- **Configurable Settings**: Adjustable error rates and virus detection rates
- **Real-time Logging**: Track all simulation activities

**Configuration:**
- Default error rate: 40%
- Default virus rate: 25%
- Email check interval: 30 seconds
- SMTP server: Gmail (customizable)

#### 2. Basic Virus Simulator (`virus_simulator.py`)
A command-line tool demonstrating basic malware scanning and detection concepts.

**Features:**
- **File Scanning**: Recursively scans directories for files
- **Simulated Infection**: Demonstrates infection process (no actual changes)
- **Detection Simulation**: 80% detection rate simulation
- **Cleaning Simulation**: Demonstrates malware removal process

**Key Points:**
- ✅ **Completely Safe**: No files are modified, deleted, or transmitted
- 📚 **Educational Purpose**: Learn about malware behavior without risk
- 🔍 **Detection Patterns**: Understand how antivirus software works

### Running the Lab
```bash
# Email virus simulator (GUI)
cd Lab3/3
python email_virus_simulator.py

# Basic virus simulator (CLI)
python virus_simulator.py
```

---

## Lab 4: Vulnerability Analysis Tool

### Overview
A professional code security scanner that identifies common vulnerabilities across multiple programming languages. Includes both CLI and web interfaces.

### Components

#### 1. Command-Line Analyzer (`4.py`)
Scans source code files and directories for security vulnerabilities.

**Supported Languages:**
- Python, JavaScript, Java, C/C++, PHP, Ruby, Go, Rust, C#, Shell scripts

**Detection Categories:**

**HIGH Severity:**
- Hardcoded credentials (API keys, passwords, tokens)
- Code injection vulnerabilities (eval, exec)
- Command injection (shell=True, os.system)
- SQL injection patterns
- Unsafe deserialization (pickle.loads)
- Insecure temporary files
- SSL/TLS verification disabled

**MEDIUM Severity:**
- Weak cryptographic algorithms (MD5, SHA1)
- Insecure file permissions
- Non-cryptographic random generators for security

**LOW Severity:**
- TODO/FIXME comments
- Debug mode enabled
- Commented-out code

#### 2. Streamlit Web Interface (`streamlit_vuln_app.py`)
Interactive web application for vulnerability analysis.

**Features:**
- 📂 **Multiple Input Methods**: File upload, code paste, or example code
- 📊 **Visual Analytics**: Pie charts, bar graphs, and distribution plots
- 🔍 **Interactive Filtering**: Filter by severity and vulnerability type
- 📥 **Export Reports**: JSON format with detailed findings
- 🎯 **Detailed Explanations**: Each finding includes fix suggestions

**Visualizations:**
- Severity distribution pie chart
- Vulnerability types bar chart
- Line-by-line issue distribution
- Risk assessment metrics

### Running the Lab
```bash
cd Lab4/4

# Command-line usage
python 4.py -f <file_path>                    # Scan single file
python 4.py -d <directory_path>               # Scan directory
python 4.py -d . --json-report report.json    # Export to JSON

# Web interface
streamlit run streamlit_vuln_app.py
# Open browser to http://localhost:8501
```

### Example Output
```
[HIGH] Hardcoded credential / secret
  File: example.py, Line: 15
  Code: api_key = "sk_test_1234567890"
  Fix: Move secrets to environment variables or secret managers
```

---

## Lab 5: Phishing URL Detector

### Overview
Machine learning-based system for detecting phishing websites using Random Forest classification with 17 advanced URL features.

### Components

#### 1. Basic Detector (`phishing_detector.py`)
Core implementation with feature extraction and model training.

**Feature Set (8 features):**
- URL length
- HTTPS usage
- Presence of @ symbol
- Hostname length
- Dot count
- Hyphen count
- Digit count
- URL shortening service detection

#### 2. Enhanced Detector (`enhanced_phishing_detector.py`)
Advanced implementation with 17 research-backed features.

**Feature Categories:**

**Address Bar Based (9 features):**
- URL length and depth
- HTTPS protocol check
- @ symbol presence
- Double slash in path
- Dash in domain
- Subdomain count
- Suspicious keywords detection
- Hostname length

**Domain Based (4 features):**
- IP address detection
- Well-known domain verification
- Dots in domain count
- Numbers in domain

**HTML & JavaScript Based (4 features):**
- URL shortening service usage
- Suspicious TLD detection (.tk, .ml, .cf, .ga, .click, etc.)
- Query parameters count
- Special characters count

#### 3. Streamlit Web Interface (`streamlit_app.py`)
Professional web application with real-time URL analysis.

**Features:**
- 🛡️ **Real-time Detection**: Instant phishing probability calculation
- 📊 **Visual Risk Assessment**: Gauge charts and probability meters
- 🔍 **Feature Breakdown**: Detailed analysis of all 17 features
- 📝 **Sample Testing**: Pre-loaded safe and malicious URLs
- 📈 **Model Performance**: Accuracy metrics and confidence scores

### Running the Lab
```bash
cd Lab5

# Install dependencies
pip install -r requirements.txt

# Train and test basic model
python phishing_detector.py

# Train enhanced model
python enhanced_phishing_detector.py

# Launch web interface
streamlit run streamlit_app.py
# Open browser to http://localhost:8501
```

### Model Performance
- **Algorithm**: Random Forest Classifier (100 estimators)
- **Accuracy**: ~95-100% on test datasets
- **Training Split**: 80/20
- **Features**: 17 extracted URL characteristics

### Usage Example
```python
from enhanced_phishing_detector import PhishingDetector

detector = PhishingDetector()
detector.load_model()

url = "http://secure-banking-update.tk/login.php"
result = detector.predict_url(url)
print(f"Prediction: {result['prediction']}")
print(f"Probability: {result['probability']:.2%}")
```

---

## Lab 7: Hash Functions & Code Obfuscation

### Overview
Comprehensive implementation of cryptographic hash functions and various code obfuscation techniques for security education.

### Components

#### 1. Hash Generator (`HashGenerator` class)
Multi-algorithm hash generation and file integrity verification.

**Supported Algorithms:**
- MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512

**Features:**
- **String Hashing**: Hash any text with chosen algorithm
- **File Hashing**: Compute file checksums with chunked reading
- **Multi-Algorithm Hashing**: Generate all hashes simultaneously
- **Hash Comparison**: Compare two strings/files
- **Integrity Verification**: Verify file checksums

#### 2. Code Obfuscator (`CodeObfuscator` class)
Various techniques to obscure Python code.

**Obfuscation Methods:**

1. **Base64 Encoding**: Simple encoding/decoding
2. **Zlib Compression**: Compress and encode code
3. **Marshal Obfuscation**: Convert to bytecode
4. **String Obfuscation**: Character code conversion
5. **Multi-layer**: Combine multiple techniques

#### 3. Streamlit Web Application (`app.py`)
Interactive web interface for all functionality.

**Features:**
- 🔐 **Hash Generation**: Interactive hash calculator
- 📁 **File Hashing**: Upload and hash files
- 🔧 **Code Obfuscation**: Real-time code transformation
- ✅ **Hash Verification**: Compare and verify hashes
- 📊 **Visual Comparison**: Side-by-side algorithm comparison

#### 4. Combined CLI Program (`combined_project.py`)
Comprehensive command-line interface with all features.

**Menu Options:**
1. Hash function demonstrations
2. Obfuscation technique demonstrations
3. Interactive hash tools
4. Interactive obfuscation tools
5. Create sample files for testing
6. Exit

### Running the Lab
```bash
cd Lab7

# Web interface
streamlit run app.py

# Command-line interface
python combined_project.py

# Individual components
python hash_functions.py
python obfuscation_techniques.py
```

### Usage Examples

**Hash Generation:**
```python
from hash_functions import HashGenerator

gen = HashGenerator()
hash_value = gen.hash_string("Hello, World!", "sha256")
print(hash_value)  # Output: SHA-256 hash

# Verify file integrity
is_valid = gen.verify_file_integrity(
    file_bytes, 
    "expected_hash", 
    "sha256"
)
```

**Code Obfuscation:**
```python
from obfuscation_techniques import CodeObfuscator

obf = CodeObfuscator()
code = "print('Hello, World!')"

# Base64 obfuscation
obfuscated = obf.base64_obfuscation(code)
print(obfuscated)
# Output: import base64\nexec(base64.b64decode('...').decode())
```

---

## Lab 8: Digital Signatures & Authentication

### Overview
Complete implementation of RSA digital signatures with JWT-based authentication system, simulating secure banking transactions.

### Components

#### 1. Digital Signature Module (`digital_signature.py`)
RSA cryptographic implementation for message signing and verification.

**Features:**
- **RSA Key Generation**: 2048-bit secure key pairs
- **Digital Signing**: SHA-256 hashing with PSS padding
- **Signature Verification**: Public key verification
- **Key Management**: Save/load PEM format keys
- **Base64 Encoding**: Safe signature transmission

**Security Specifications:**
- Key size: 2048 bits (NIST recommended)
- Hash function: SHA-256
- Padding: PSS (Probabilistic Signature Scheme)
- Encoding: PEM format

#### 2. Secure Banking Application (`secure_banking_app.py`)
Flask-based web application with JWT authentication and role-based access control.

**Features:**
- 🔐 **JWT Authentication**: Secure token-based login
- 👥 **Role-Based Access Control**: Customer, Merchant, Admin roles
- 💰 **Transaction Management**: Digitally signed transactions
- ✍️ **Signature Verification**: Cryptographic transaction validation
- 📊 **Transaction Logging**: Complete audit trail

**User Roles:**

**Customer:**
- View account balance
- Create signed transactions
- View transaction history

**Merchant:**
- Accept payments
- Verify transaction signatures
- View merchant transactions

**Admin:**
- View all transactions
- Verify any signature
- System monitoring

**Default Credentials:**
```
Customer: customer1 / password123
Merchant: merchant1 / merchant123
Admin: bank_admin / admin123
```

#### 3. Test Suite (`test_suite.py`)
Comprehensive testing framework.

**Test Categories:**
- Unit tests for digital signatures
- Integration tests for authentication
- Transaction flow testing
- Security edge cases
- Performance benchmarks

#### 4. Case Study Analysis (`case_study_analysis.md`)
In-depth analysis of digital signatures in e-commerce and banking.

**Topics Covered:**
- Real-world applications
- Security benefits and vulnerabilities
- Regulatory compliance (PKI, e-SIGN Act, eIDAS)
- Economic impact analysis
- Future trends and blockchain integration

### Running the Lab
```bash
cd Lab8

# Install dependencies
pip install -r requirements.txt

# Run web application
python secure_banking_app.py
# Access at http://localhost:5000

# Run test suite
python test_suite.py

# Digital signature demo
python digital_signature.py
```

### API Endpoints

**Authentication:**
```bash
POST /login
Body: {"username": "customer1", "password": "password123"}
Returns: {"access_token": "jwt_token"}
```

**Transactions:**
```bash
POST /transaction
Headers: Authorization: Bearer <token>
Body: {
    "recipient": "merchant1",
    "amount": 100.0,
    "description": "Purchase"
}
```

**Signature Verification:**
```bash
POST /verify-signature
Headers: Authorization: Bearer <token>
Body: {
    "transaction_id": "txn_123",
    "signature": "base64_signature"
}
```

### Usage Example
```python
from digital_signature import RSADigitalSignature

# Generate keys
sig = RSADigitalSignature()
private_key, public_key = sig.generate_key_pair()

# Sign message
message = "Transfer $100 to merchant1"
signature = sig.sign_message(message)

# Verify signature
is_valid = sig.verify_signature(message, signature)
print(f"Signature valid: {is_valid}")
```

---

## Lab 9: Data Privacy & Anonymization

### Overview
Implementation of privacy-preserving techniques including PII detection, data classification, k-anonymity, and l-diversity for protecting sensitive information.

### Components

#### 1. PII Detector (`9a.py`)
Streamlit application for detecting Personally Identifiable Information.

**Detection Patterns:**
- **Names**: Patient/person name patterns
- **Email Addresses**: RFC-compliant email detection
- **Phone Numbers**: US format phone numbers
- **SSN**: Social Security Number patterns
- **Credit Cards**: Visa card number detection

**Data Classification:**
- **Structured Data**: JSON, CSV formats
- **Unstructured Data**: Free text, documents
- **Data State Analysis**: At-rest, in-use, in-transit

**Features:**
- 🔍 **Real-time PII Detection**: Instant pattern matching
- 📊 **Data Classification**: Automatic type detection
- 🎯 **Multiple PII Types**: Names, emails, phones, SSN, credit cards
- 📝 **Sample Data Testing**: Pre-loaded examples

#### 2. K-Anonymity & L-Diversity Tool (`9b.py`)
Advanced privacy preservation through data generalization.

**Privacy Techniques:**

**K-Anonymity:**
- Ensures each record is indistinguishable from at least k-1 others
- Uses quasi-identifiers (Age, Zip Code)
- Generalization techniques for privacy

**L-Diversity:**
- Ensures diversity of sensitive attributes
- Prevents attribute disclosure attacks
- Configurable diversity threshold

**Generalization Methods:**
- **Age Generalization**: Bin ages into ranges (e.g., 30-34)
- **Zip Code Generalization**: Mask digits (e.g., 1234* from 12345)
- **Equivalence Classes**: Group similar records

**Features:**
- 📊 **CSV Data Upload**: Process real datasets
- 🔧 **Configurable Parameters**: Set k and l values
- 📈 **Risk Metrics**: Re-identification risk analysis
- 📉 **Anonymization Levels**: Progressive generalization
- 📋 **Before/After Comparison**: Visualize privacy impact

**Risk Metrics:**
- Minimum equivalence class size
- Average equivalence class size
- Naive re-identification risk
- Unique record fraction

### Running the Lab
```bash
cd lab9

# PII Detector
streamlit run 9a.py
# Open browser to http://localhost:8501

# K-Anonymity Tool
streamlit run 9b.py
# Upload CSV or use sample data
```

### Usage Examples

**PII Detection:**
```
Input Text:
"Patient Name: John Smith
Email: john.smith@email.com
Phone: (555) 123-4567
SSN: 123-45-6789"

Output:
✓ Found NAME: ['John Smith']
✓ Found EMAIL: ['john.smith@email.com']
✓ Found PHONE_NUMBER_US: ['(555) 123-4567']
✓ Found SSN_US: ['123-45-6789']
```

**K-Anonymity Example:**
```
Original Data:
| Name  | Age | Zip   | Disease |
| ----- | --- | ----- | ------- |
| Alice | 25  | 12345 | Flu     |
| Bob   | 27  | 12346 | Cold    |

After 2-Anonymity (Age bins=5, Zip level=1):
| Name  | Age   | Zip   | Disease |
| ----- | ----- | ----- | ------- |
| Alice | 25-29 | 1234* | Flu     |
| Bob   | 25-29 | 1234* | Cold    |

Result: Each record now indistinguishable from 1 other
```

### Sample CSV Format
```csv
Name,Age,Zip,Disease
Alice,25,12345,Flu
Bob,27,12346,Cold
Charlie,25,12347,Diabetes
```

---

## Setup Instructions

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### General Installation

1. **Clone or download the repository**
```bash
cd dsp_labs_1ds23ai405
```

2. **Install dependencies for each lab**
```bash
# Lab 4
cd Lab4/4
pip install -r requirements_streamlit.txt

# Lab 5
cd ../../Lab5
pip install -r requirements.txt

# Lab 7
cd ../Lab7
# No external dependencies required

# Lab 8
cd ../Lab8
pip install -r requirements.txt

# Lab 9
cd ../lab9
pip install streamlit pandas numpy
```

### Common Dependencies
```bash
# Core libraries used across labs
pip install streamlit pandas numpy scikit-learn
pip install flask flask-jwt-extended cryptography
pip install plotly requests
```

### Running Individual Labs

**Lab 3 (Virus Simulation):**
```bash
cd Lab3/3
python virus_simulator.py
```

**Lab 4 (Vulnerability Scanner):**
```bash
cd Lab4/4
streamlit run streamlit_vuln_app.py
```

**Lab 5 (Phishing Detector):**
```bash
cd Lab5
streamlit run streamlit_app.py
```

**Lab 7 (Hash & Obfuscation):**
```bash
cd Lab7
streamlit run app.py
```

**Lab 8 (Digital Signatures):**
```bash
cd Lab8
python secure_banking_app.py
```

**Lab 9 (Privacy Tools):**
```bash
cd lab9
streamlit run 9a.py  # PII Detector
streamlit run 9b.py  # K-Anonymity
```

---

## Key Learning Outcomes

### Security Concepts
- ✅ Malware behavior simulation and detection
- ✅ Vulnerability analysis across multiple languages
- ✅ Phishing detection using machine learning
- ✅ Cryptographic hash functions and integrity verification
- ✅ Code obfuscation techniques
- ✅ Digital signatures and PKI
- ✅ JWT authentication and authorization
- ✅ Role-based access control

### Privacy & Data Protection
- ✅ PII detection and classification
- ✅ K-anonymity implementation
- ✅ L-diversity for sensitive data
- ✅ Data generalization techniques
- ✅ Re-identification risk assessment

### Technical Skills
- ✅ Python programming for security
- ✅ Machine learning for threat detection
- ✅ Web application development (Flask, Streamlit)
- ✅ Cryptography implementation
- ✅ Data privacy algorithms
- ✅ GUI development (Tkinter)
- ✅ API development and testing

---

## Technologies Used

### Programming Languages
- Python 3.7+

### Frameworks & Libraries
- **Web**: Flask, Streamlit
- **ML**: Scikit-learn, Pandas, NumPy
- **Crypto**: cryptography, hashlib
- **Visualization**: Plotly, Matplotlib
- **GUI**: Tkinter
- **Auth**: Flask-JWT-Extended

### Security Tools
- RSA cryptography
- SHA family hash functions
- JWT tokens
- Regular expressions for pattern matching

---

## Important Notes

### ⚠️ Educational Purpose Only
All tools in this repository are for **educational purposes only**:
- The virus simulators do NOT harm any files
- The vulnerability scanner is for learning, not production use
- Use phishing detector on authorized URLs only
- Digital signatures are for demonstration, not production banking

### 🔒 Security Best Practices
- Never hardcode credentials in production code
- Use environment variables for sensitive data
- Implement proper error handling
- Validate all user inputs
- Use secure random number generators
- Keep dependencies updated
- Follow principle of least privilege

### 📝 Usage Guidelines
- Test in isolated environments
- Do not use on unauthorized systems
- Respect privacy and data protection laws
- Follow responsible disclosure for real vulnerabilities
- Obtain proper authorization before security testing

---

## Contributing

This is an educational project. For improvements or bug fixes:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

This project is created for academic purposes as part of the Digital Security & Privacy course.

---

## Contact

**Student:** 1DS23AI405  
**Course:** Digital Security & Privacy (DSP)

---

## Acknowledgments

- Course instructors and teaching assistants
- Python security community
- Open-source libraries and frameworks
- Research papers on phishing detection and privacy preservation

---

**Last Updated:** November 2025
