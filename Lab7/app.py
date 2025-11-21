"""
This file combines all the functionality of the project into a single Streamlit application.
It includes hash functions, obfuscation techniques, practical examples, and tests, all accessible through a web interface.
"""

import streamlit as st
import hashlib
import os
from typing import Union, Optional
import base64
import marshal
import types
import zlib
import ast
import random
import string
import json
import time
import sys
import traceback
from io import StringIO

# --- Core Logic Classes (from the original project) ---

class HashGenerator:
    """A class to generate various hash values for strings and files"""
    
    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }
    
    def hash_string(self, text: str, algorithm: str = 'sha256') -> str:
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def hash_file(self, file_bytes: bytes, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        
        # Process bytes directly
        offset = 0
        while chunk := file_bytes[offset:offset + chunk_size]:
            hash_obj.update(chunk)
            offset += chunk_size
        
        return hash_obj.hexdigest()

    def hash_multiple_algorithms(self, text: str) -> dict:
        results = {}
        for algorithm in self.supported_algorithms:
            results[algorithm] = self.hash_string(text, algorithm)
        return results
    
    def compare_hashes(self, text1: str, text2: str, algorithm: str = 'sha256') -> bool:
        hash1 = self.hash_string(text1, algorithm)
        hash2 = self.hash_string(text2, algorithm)
        return hash1 == hash2
    
    def verify_file_integrity(self, file_bytes: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
        actual_hash = self.hash_file(file_bytes, algorithm)
        return actual_hash.lower() == expected_hash.lower()

class CodeObfuscator:
    """A class to demonstrate various code obfuscation techniques"""
    
    def __init__(self):
        self.variable_mapping = {}
        self.function_mapping = {}
    
    def base64_obfuscation(self, code: str) -> str:
        encoded_code = base64.b64encode(code.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{encoded_code}').decode())"
    
    def zlib_compression_obfuscation(self, code: str) -> str:
        compressed = zlib.compress(code.encode())
        encoded = base64.b64encode(compressed).decode()
        return f"import zlib, base64\nexec(zlib.decompress(base64.b64decode('{encoded}')).decode())"
    
    def marshal_obfuscation(self, code: str) -> str:
        compiled_code = compile(code, '<string>', 'exec')
        marshaled = marshal.dumps(compiled_code)
        encoded = base64.b64encode(marshaled).decode()
        return f"import marshal, base64\nexec(marshal.loads(base64.b64decode('{encoded}')))"
    
    def string_obfuscation(self, text: str) -> str:
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"
    
    def multilayer_obfuscation(self, code: str) -> str:
        obfuscated = self.zlib_compression_obfuscation(code)
        obfuscated = self.base64_obfuscation(obfuscated)
        return obfuscated

class ObfuscatedFunction:
    """Example of an obfuscated function class"""
    
    def hidden_calculation(self, x: int, y: int) -> int:
        a = x.__mul__(y)
        b = a.__add__(10)
        return b
    
    def reveal_secret(self, password: str) -> str:
        correct_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        provided_hash = hashlib.sha256(password.encode()).hexdigest()
        if provided_hash == correct_hash:
            secret = self._string_obfuscation("The secret is: Code obfuscation is a technique to make code harder to understand!")
            return eval(secret)
        else:
            return "Access denied!"
    
    def _string_obfuscation(self, text: str) -> str:
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"

class PasswordManager:
    """Simple password manager demonstrating hash function usage"""
    def __init__(self, session_state):
        self.hasher = HashGenerator()
        if 'users' not in session_state:
            session_state['users'] = {}
        self.users = session_state['users']

    def hash_password(self, password: str, salt: str = None) -> tuple:
        if salt is None:
            salt = os.urandom(32).hex()
        salted_password = password + salt
        password_hash = self.hasher.hash_string(salted_password, 'sha256')
        return password_hash, salt

    def register_user(self, username: str, password: str) -> bool:
        if username in self.users:
            return False
        password_hash, salt = self.hash_password(password)
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'created_at': time.time()
        }
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        if username not in self.users:
            return False
        user_data = self.users[username]
        salt = user_data['salt']
        stored_hash = user_data['password_hash']
        provided_hash, _ = self.hash_password(password, salt)
        return provided_hash == stored_hash

class FileIntegrityChecker:
    """File integrity checker using hash functions"""
    def __init__(self, session_state):
        self.hasher = HashGenerator()
        if 'file_hashes' not in session_state:
            session_state['file_hashes'] = {}
        self.file_hashes = session_state['file_hashes']

    def add_file(self, file_name: str, file_bytes: bytes) -> str:
        file_hash = self.hasher.hash_file(file_bytes, 'sha256')
        self.file_hashes[file_name] = {
            'hash': file_hash,
            'size': len(file_bytes),
            'added_at': time.time(),
        }
        return file_hash

    def check_file(self, file_name: str, file_bytes: bytes) -> dict:
        if file_name not in self.file_hashes:
            return {'status': 'not_monitored', 'message': 'File is not being monitored'}
        
        stored_data = self.file_hashes[file_name]
        current_hash = self.hasher.hash_file(file_bytes, 'sha256')
        current_size = len(file_bytes)

        if current_hash == stored_data['hash'] and current_size == stored_data['size']:
            return {'status': 'unchanged', 'message': 'File is unchanged'}
        else:
            return {
                'status': 'modified',
                'message': 'File has been modified',
                'original_hash': stored_data['hash'],
                'current_hash': current_hash,
            }

class LicenseKeyGenerator:
    """Obfuscated license key generator"""
    def __init__(self):
        self.hasher = HashGenerator()

    def generate_license_key(self, user_id: str, product_code: str) -> str:
        unique_string = f"{user_id}:{product_code}:{time.time()}"
        hash_value = self.hasher.hash_string(unique_string, 'sha256')
        key_core = hash_value[:16].upper()
        
        parts = [key_core[i:i+4] for i in range(0, len(key_core), 4)]
        formatted_key = f"LIC-{''.join(parts)}-2024"
        return formatted_key

    def validate_license_key(self, license_key: str) -> bool:
        if not license_key.startswith('LIC-') or not license_key.endswith('-2024'):
            return False
        parts = license_key.split('-')
        if len(parts) != 3:
            return False
        key_core = parts[1]
        return len(key_core) == 16 and all(c in string.hexdigits for c in key_core)

# --- UI Functions ---

def show_hash_functions():
    st.markdown('<h1 class="main-header">🔐 Hash Functions</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Add metrics at the top
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔢 Supported Algorithms", "6", "MD5, SHA1, SHA2 family")
    with col2:
        st.metric("🛡️ Security Level", "High", "SHA-256/512 recommended")
    with col3:
        st.metric("⚡ Performance", "Fast", "Optimized for speed")
    
    st.markdown("---")
    hasher = HashGenerator()
    
    tab1, tab2 = st.tabs(["🎮 Interactive Demo", "📊 Avalanche Effect Demo"])

    with tab1:
        st.subheader("Interactive Hashing")
        option = st.selectbox("Choose an operation", ["Hash a string", "Hash a file", "Compare two strings"])

        if option == "Hash a string":
            st.markdown("#### 📝 Text Input")
            text = st.text_input("🔤 Enter text to hash:", placeholder="Type your text here...")
            
            col1, col2 = st.columns([2, 1])
            with col1:
                algorithm = st.selectbox("🔧 Select algorithm", list(hasher.supported_algorithms.keys()), index=2)
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                generate_btn = st.button("🚀 Generate Hash", type="primary")
            
            if generate_btn:
                if text:
                    hash_value = hasher.hash_string(text, algorithm)
                    st.markdown("#### ✅ Result")
                    st.success(f"**{algorithm.upper()} Hash Generated Successfully!**")
                    
                    # Display hash in a nice container
                    st.markdown("""
                    <div style="background: #f8f9fa; padding: 1rem; border-radius: 10px; border-left: 4px solid #28a745; margin: 1rem 0;">
                        <h5 style="margin: 0; color: #28a745;">🔐 Hash Output:</h5>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(hash_value, language="")
                    
                    # Add copy button info
                    st.info("💡 **Tip:** Click on the hash above to copy it to your clipboard!")
                else:
                    st.error("❌ Please enter some text to hash.")

        elif option == "Hash a file":
            st.markdown("#### 📁 File Upload")
            uploaded_file = st.file_uploader(
                "🔍 Choose a file to hash", 
                help="Upload any file type to generate its hash"
            )
            
            col1, col2 = st.columns([2, 1])
            with col1:
                algorithm = st.selectbox("🔧 Select algorithm ", list(hasher.supported_algorithms.keys()), index=2)
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                hash_btn = st.button("🔐 Generate File Hash", type="primary")
            
            if hash_btn:
                if uploaded_file is not None:
                    file_bytes = uploaded_file.getvalue()
                    hash_value = hasher.hash_file(file_bytes, algorithm)
                    
                    st.markdown("#### ✅ File Hash Result")
                    
                    # File info
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("📄 File Name", uploaded_file.name)
                    with col2:
                        st.metric("📊 File Size", f"{len(file_bytes)} bytes")
                    with col3:
                        st.metric("🔧 Algorithm", algorithm.upper())
                    
                    st.success(f"**{algorithm.upper()} Hash Generated Successfully!**")
                    
                    # Display hash in a nice container
                    st.markdown("""
                    <div style="background: #f8f9fa; padding: 1rem; border-radius: 10px; border-left: 4px solid #17a2b8; margin: 1rem 0;">
                        <h5 style="margin: 0; color: #17a2b8;">🔐 File Hash:</h5>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(hash_value, language="")
                    
                    st.info("💡 **Use Case:** File integrity verification, detecting changes, digital forensics")
                else:
                    st.error("❌ Please upload a file first.")

        elif option == "Compare two strings":
            st.markdown("#### ⚖️ String Comparison")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**📝 First String:**")
                text1 = st.text_area("Enter first string:", height=100, placeholder="Type first text here...")
            with col2:
                st.markdown("**📝 Second String:**")
                text2 = st.text_area("Enter second string:", height=100, placeholder="Type second text here...")
            
            col1, col2 = st.columns([2, 1])
            with col1:
                algorithm = st.selectbox("🔧 Select algorithm  ", list(hasher.supported_algorithms.keys()), index=2)
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                compare_btn = st.button("🔍 Compare Hashes", type="primary")
            
            if compare_btn:
                if text1 and text2:
                    are_same = hasher.compare_hashes(text1, text2, algorithm)
                    hash1 = hasher.hash_string(text1, algorithm)
                    hash2 = hasher.hash_string(text2, algorithm)
                    
                    st.markdown("#### 📊 Comparison Results")
                    
                    if are_same:
                        st.success("✅ The hashes are **IDENTICAL** - Strings match!")
                        st.balloons()
                    else:
                        st.error("❌ The hashes are **DIFFERENT** - Strings don't match!")
                    
                    # Display hashes in comparison format
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("""
                        <div style="background: #e3f2fd; padding: 1rem; border-radius: 10px; border-left: 4px solid #2196f3;">
                            <h5 style="margin: 0; color: #1976d2;">🔵 Hash 1:</h5>
                        </div>
                        """, unsafe_allow_html=True)
                        st.code(hash1, language="")
                    with col2:
                        st.markdown("""
                        <div style="background: #f3e5f5; padding: 1rem; border-radius: 10px; border-left: 4px solid #9c27b0;">
                            <h5 style="margin: 0; color: #7b1fa2;">🟣 Hash 2:</h5>
                        </div>
                        """, unsafe_allow_html=True)
                        st.code(hash2, language="")
                else:
                    st.warning("⚠️ Please enter text in both fields to compare.")

    with tab2:
        st.markdown("#### 🌊 Avalanche Effect Demonstration")
        st.markdown("""
        <div style="background: #fff3e0; padding: 1rem; border-radius: 10px; border-left: 4px solid #ff9800; margin: 1rem 0;">
            <h5 style="margin: 0; color: #f57c00;">📚 What is the Avalanche Effect?</h5>
            <p style="margin: 0.5rem 0 0 0;">A small change in input produces a dramatically different output.</p>
        </div>
        """, unsafe_allow_html=True)
        
        original = "password"
        modified = "Password"
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            <div style="background: #e8f5e8; padding: 1rem; border-radius: 10px; border-left: 4px solid #4caf50;">
                <h5 style="margin: 0; color: #388e3c;">🔤 Original Text:</h5>
                <p style="font-family: monospace; font-size: 1.2rem; margin: 0.5rem 0 0 0;">password</p>
            </div>
            """, unsafe_allow_html=True)
            
            hash_orig = hasher.hash_string(original)
            st.markdown("**🔐 SHA-256 Hash:**")
            st.code(hash_orig, language="")
            
        with col2:
            st.markdown("""
            <div style="background: #fce4ec; padding: 1rem; border-radius: 10px; border-left: 4px solid #e91e63;">
                <h5 style="margin: 0; color: #c2185b;">🔤 Modified Text:</h5>
                <p style="font-family: monospace; font-size: 1.2rem; margin: 0.5rem 0 0 0;">Password <span style="background: yellow;">(P capitalized)</span></p>
            </div>
            """, unsafe_allow_html=True)
            
            hash_mod = hasher.hash_string(modified)
            st.markdown("**🔐 SHA-256 Hash:**")
            st.code(hash_mod, language="")
        
        st.markdown("""
        <div style="background: #e3f2fd; padding: 1rem; border-radius: 10px; margin: 1rem 0; text-align: center;">
            <h4 style="margin: 0; color: #1976d2;">🎯 Key Observation</h4>
            <p style="margin: 0.5rem 0 0 0;">Changing just <strong>one character</strong> resulted in a <strong>completely different hash</strong>!</p>
            <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: #666;">This property makes hash functions excellent for detecting even tiny changes in data.</p>
        </div>
        """, unsafe_allow_html=True)

def show_obfuscation():
    st.markdown('<h1 class="main-header">🎭 Code Obfuscation</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Add info cards
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info("🔒 **Purpose**\nMake code harder to understand")
    with col2:
        st.warning("⚠️ **Security**\nNot foolproof protection")
    with col3:
        st.success("🎯 **Use Cases**\nIP protection, anti-reverse")
    
    st.markdown("---")
    obfuscator = CodeObfuscator()
    
    tab1, tab2 = st.tabs(["🛠️ Code Obfuscator", "🎪 Live Examples"])

    with tab1:
        st.markdown("#### 🛠️ Code Transformation Tool")
        
        # Input section
        st.markdown("**📝 Source Code:**")
        code = st.text_area(
            "Enter Python code to obfuscate:", 
            height=150, 
            value="print('Hello from obfuscated code!')\nname = 'Security Demo'\nprint(f'Welcome to {name}')",
            help="Enter any valid Python code to see different obfuscation techniques"
        )
        
        col1, col2 = st.columns([2, 1])
        with col1:
            method = st.selectbox(
                "🔧 Choose obfuscation method", 
                ["Base64", "Zlib + Base64", "Marshal + Base64", "Multilayer"],
                help="Different methods provide varying levels of obfuscation"
            )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            obfuscate_btn = st.button("🎭 Obfuscate Code", type="primary")
        
        if obfuscate_btn:
            if code.strip():
                try:
                    if method == "Base64":
                        obfuscated_code = obfuscator.base64_obfuscation(code)
                    elif method == "Zlib + Base64":
                        obfuscated_code = obfuscator.zlib_compression_obfuscation(code)
                    elif method == "Marshal + Base64":
                        obfuscated_code = obfuscator.marshal_obfuscation(code)
                    elif method == "Multilayer":
                        obfuscated_code = obfuscator.multilayer_obfuscation(code)
                    
                    st.markdown("#### 🎭 Obfuscated Result")
                    
                    # Show compression ratio
                    original_size = len(code)
                    obfuscated_size = len(obfuscated_code)
                    ratio = obfuscated_size / original_size
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("📏 Original Size", f"{original_size} chars")
                    with col2:
                        st.metric("📏 Obfuscated Size", f"{obfuscated_size} chars")
                    with col3:
                        st.metric("📊 Size Ratio", f"{ratio:.2f}x")
                    
                    st.markdown("""
                    <div style="background: #f8f9fa; padding: 1rem; border-radius: 10px; border-left: 4px solid #6f42c1; margin: 1rem 0;">
                        <h5 style="margin: 0; color: #6f42c1;">🎭 Obfuscated Code:</h5>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(obfuscated_code, language="python")

                    with st.expander("🚀 Execute Obfuscated Code?", expanded=False):
                        st.warning("⚠️ **Security Notice:** Executing arbitrary code can be risky in production environments.")
                        if st.button("✅ Yes, execute it safely", type="secondary"):
                            old_stdout = sys.stdout
                            sys.stdout = mystdout = StringIO()
                            try:
                                exec(obfuscated_code, {})
                                sys.stdout = old_stdout
                                output = mystdout.getvalue()
                                
                                st.markdown("#### 📤 Execution Output")
                                if output.strip():
                                    st.success("✅ Code executed successfully!")
                                    st.code(output, language="text")
                                else:
                                    st.info("ℹ️ Code executed successfully with no output.")
                            except Exception as e:
                                sys.stdout = old_stdout
                                st.error(f"❌ Execution failed: {str(e)}")
                                
                except Exception as e:
                    st.error(f"❌ Obfuscation failed: {str(e)}")
            else:
                st.warning("⚠️ Please enter some code to obfuscate.")

    with tab2:
        st.subheader("Obfuscated Function Example")
        obf_func = ObfuscatedFunction()
        
        st.write("This demonstrates a function with hidden logic.")
        col1, col2 = st.columns(2)
        with col1:
            x = st.number_input("Enter first number (x)", value=7)
        with col2:
            y = st.number_input("Enter second number (y)", value=6)
        
        result = obf_func.hidden_calculation(x, y)
        st.write(f"The obfuscated calculation is `x * y + 10`.")
        st.success(f"Result of hidden calculation: {result}")

        st.subheader("Secret Reveal")
        password = st.text_input("Enter password to reveal secret:", type="password")
        if st.button("Reveal Secret"):
            secret = obf_func.reveal_secret(password)
            if "Access denied" in secret:
                st.error(secret)
            else:
                st.success(secret)
            st.info("The correct password is `secret123`")

def show_practical_examples():
    st.markdown('<h1 class="main-header">💼 Practical Examples</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    st.markdown("""
    <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 1rem; border-radius: 10px; margin-bottom: 2rem;">
        <h3 style="color: white; margin: 0;">🎯 Real-world Applications</h3>
        <p style="color: white; margin: 0.5rem 0 0 0;">Explore practical implementations of hash functions and obfuscation in security systems.</p>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("🔐 1. Password Manager", expanded=True):
        pm = PasswordManager(st.session_state)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 👤 User Registration")
            with st.container():
                reg_user = st.text_input("👤 Username", key="reg_user", placeholder="Enter username")
                reg_pass = st.text_input("🔒 Password", type="password", key="reg_pass", placeholder="Enter secure password")
                if st.button("✅ Register User", type="primary", use_container_width=True):
                    if reg_user and reg_pass:
                        if pm.register_user(reg_user, reg_pass):
                            st.success(f"🎉 User '{reg_user}' registered successfully!")
                            st.balloons()
                        else:
                            st.error(f"❌ User '{reg_user}' already exists.")
                    else:
                        st.warning("⚠️ Please fill in both fields.")

        with col2:
            st.markdown("#### 🔓 User Authentication")
            with st.container():
                auth_user = st.text_input("👤 Username", key="auth_user", placeholder="Enter username")
                auth_pass = st.text_input("🔒 Password", type="password", key="auth_pass", placeholder="Enter password")
                if st.button("🔍 Authenticate", type="secondary", use_container_width=True):
                    if auth_user and auth_pass:
                        if pm.authenticate_user(auth_user, auth_pass):
                            st.success("✅ Authentication successful!")
                            st.balloons()
                        else:
                            st.error("❌ Authentication failed.")
                    else:
                        st.warning("⚠️ Please fill in both fields.")
        
        st.markdown("---")
        if st.checkbox("👀 Show registered users (for demo)"):
            users = st.session_state.get('users', {})
            if users:
                st.markdown(f"**📊 Total Users:** {len(users)}")
                for username, data in users.items():
                    st.markdown(f"• **{username}** (registered: {time.ctime(data['created_at'])})")
            else:
                st.info("No users registered yet.")

    with st.expander("2. File Integrity Checker"):
        fic = FileIntegrityChecker(st.session_state)
        st.subheader("Monitor a File")
        monitored_file = st.file_uploader("Upload a file to add to monitoring", key="monitor_file")
        if st.button("Add to Monitoring"):
            if monitored_file:
                file_hash = fic.add_file(monitored_file.name, monitored_file.getvalue())
                st.success(f"File `{monitored_file.name}` added with hash: `{file_hash}`")
            else:
                st.warning("Please upload a file.")

        st.subheader("Check a File")
        checked_file = st.file_uploader("Upload a file to check its integrity", key="check_file")
        if st.button("Check Integrity"):
            if checked_file:
                result = fic.check_file(checked_file.name, checked_file.getvalue())
                if result['status'] == 'unchanged':
                    st.success(result['message'])
                elif result['status'] == 'modified':
                    st.warning(result['message'])
                    st.write(f"Original Hash: `{result['original_hash']}`")
                    st.write(f"Current Hash: `{result['current_hash']}`")
                else:
                    st.info(result['message'])
            else:
                st.warning("Please upload a file.")

        if st.checkbox("Show monitored files (for demo)"):
            st.json(st.session_state.get('file_hashes', {}))

    with st.expander("3. Obfuscated License Key Generator"):
        lkg = LicenseKeyGenerator()
        st.subheader("Generate License Key")
        user_id = st.text_input("User ID", value="user123")
        product_code = st.text_input("Product Code", value="PROD001")
        if st.button("Generate Key"):
            key = lkg.generate_license_key(user_id, product_code)
            st.success("Generated License Key:")
            st.code(key, language="")

        st.subheader("Validate License Key")
        key_to_validate = st.text_input("License Key to Validate")
        if st.button("Validate Key"):
            if lkg.validate_license_key(key_to_validate):
                st.success("License key is valid.")
            else:
                st.error("License key is invalid.")

def show_tests():
    st.markdown('<h1 class="main-header">🧪 Test Suite</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    st.markdown("""
    <div style="background: #f8f9fa; padding: 1rem; border-radius: 10px; border-left: 4px solid #28a745;">
        <h4 style="margin: 0; color: #28a745;">🔬 Automated Testing</h4>
        <p style="margin: 0.5rem 0 0 0;">Run comprehensive tests to verify all functionality works correctly.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 Run All Tests", use_container_width=True):
            with st.spinner("Running tests..."):
                # Redirect stdout to capture test results
                old_stdout = sys.stdout
                sys.stdout = mystdout = StringIO()

                # Mock functions from the original test script that are not available in Streamlit
                def mock_demonstrate_practical_applications():
                    pass
                
                original_practical_demo = None
                if 'demonstrate_practical_applications' in globals():
                    original_practical_demo = globals()['demonstrate_practical_applications']
                    globals()['demonstrate_practical_applications'] = mock_demonstrate_practical_applications

                # Test functions from the original project
                def test_hash_functions():
                    print("Testing Hash Functions...")
                    try:
                        hasher = HashGenerator()
                        test_hash = hasher.hash_string("test", "sha256")
                        expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                        assert test_hash == expected
                        assert len(hasher.hash_multiple_algorithms("test")) == 6
                        assert hasher.compare_hashes("same", "same")
                        print("✓ Hash Functions: All tests passed")
                        return True
                    except Exception as e:
                        print(f"✗ Hash Functions: Test failed - {e}")
                        return False

                def test_obfuscation():
                    print("Testing Obfuscation Techniques...")
                    try:
                        obfuscator = CodeObfuscator()
                        original_code = "print('Hello, World!')"
                        obfuscated = obfuscator.base64_obfuscation(original_code)
                        assert "base64" in obfuscated and "exec" in obfuscated
                        obf_func = ObfuscatedFunction()
                        assert obf_func.hidden_calculation(5, 6) == 40
                        print("✓ Obfuscation: All tests passed")
                        return True
                    except Exception as e:
                        print(f"✗ Obfuscation: Test failed - {e}")
                        return False

                def run_all_tests():
                    tests = [test_hash_functions, test_obfuscation]
                    passed = sum(1 for test in tests if test())
                    print("\n" + "=" * 60)
                    print(f"TEST RESULTS: {passed}/{len(tests)} tests passed")
                    print("=" * 60)

                run_all_tests()
                
                # Restore stdout and globals
                sys.stdout = old_stdout
                if original_practical_demo:
                    globals()['demonstrate_practical_applications'] = original_practical_demo

            st.markdown("#### 📊 Test Results")
            st.code(mystdout.getvalue(), language="text")

def add_custom_css():
    st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .stButton > button {
        background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 20px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin: 1rem 0;
    }
    
    .success-box {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
    
    .warning-box {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

def main():
    add_custom_css()
    
    # Enhanced sidebar with icons
    st.sidebar.markdown("### 🔐 Navigation Menu")
    st.sidebar.markdown("---")
    
    # Navigation with icons
    nav_options = {
        "🔐 Hash Functions": "Hash Functions",
        "🎭 Code Obfuscation": "Code Obfuscation",
        "💼 Practical Examples": "Practical Examples",
        "🧪 Run Tests": "Run Tests"
    }
    
    choice_display = st.sidebar.radio(
        "Choose a section:",
        list(nav_options.keys()),
        index=0
    )
    choice = nav_options[choice_display]
    
    # Add some info in sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ About")
    st.sidebar.info(
        "This application demonstrates hash functions and code obfuscation techniques "
        "for educational purposes in cybersecurity."
    )
    
    # Add current time
    st.sidebar.markdown(f"**🕐 Current Time:** {time.strftime('%H:%M:%S')}")
    
    if choice == "Hash Functions":
        show_hash_functions()
    elif choice == "Code Obfuscation":
        show_obfuscation()
    elif choice == "Practical Examples":
        show_practical_examples()
    elif choice == "Run Tests":
        show_tests()

if __name__ == "__main__":
    st.set_page_config(
        page_title="🔐 Security Concepts Demo", 
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Main title with enhanced styling
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0;">
        <h1 style="font-size: 3.5rem; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0.5rem;">🔐 Security Concepts</h1>
        <h2 style="color: #666; font-weight: 300; margin-top: 0;">Hash Functions & Code Obfuscation Demo</h2>
        <p style="color: #888; font-size: 1.1rem;">🎓 Educational platform for cybersecurity concepts</p>
    </div>
    """, unsafe_allow_html=True)
    
    main()
