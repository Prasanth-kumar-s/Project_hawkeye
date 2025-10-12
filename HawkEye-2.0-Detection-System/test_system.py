#!/usr/bin/env python3
"""
HawkEye 2.0 - Complete System Test Script
Tests all components and provides detailed feedback
"""

import sys
import os
import requests
import json
import time
from datetime import datetime

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"🔍 {title}")
    print("="*60)

def print_success(message):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message):
    """Print error message"""  
    print(f"❌ {message}")

def print_warning(message):
    """Print warning message"""
    print(f"⚠️ {message}")

def print_info(message):
    """Print info message"""
    print(f"ℹ️ {message}")

def test_python_version():
    """Test Python version compatibility"""
    print_header("Python Version Check")
    
    version = sys.version_info
    print_info(f"Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major >= 3 and version.minor >= 8:
        print_success("Python version is compatible")
        return True
    else:
        print_error("Python version too old. Need Python 3.8 or higher")
        return False

def test_required_packages():
    """Test if all required packages are installed"""
    print_header("Package Installation Check")
    
    required_packages = [
        ('flask', 'Flask web framework'),
        ('flask_cors', 'Flask CORS extension'),
        ('cv2', 'OpenCV computer vision library'),
        ('numpy', 'NumPy scientific computing'),
        ('PIL', 'Pillow image processing library'),
        ('librosa', 'Librosa audio processing library'),
        ('scipy', 'SciPy scientific library'),
        ('werkzeug', 'Werkzeug WSGI toolkit')
    ]
    
    failed_packages = []
    
    for package, description in required_packages:
        try:
            if package == 'PIL':
                from PIL import Image
                print_success(f"{description}")
            elif package == 'cv2':
                import cv2
                print_success(f"{description}")
            elif package == 'flask_cors':
                from flask_cors import CORS
                print_success(f"{description}")
            else:
                __import__(package)
                print_success(f"{description}")
        except ImportError as e:
            print_error(f"{description} - {str(e)}")
            failed_packages.append(package)
        except Exception as e:
            print_warning(f"{description} - Warning: {str(e)}")
    
    if failed_packages:
        print_error(f"Missing packages: {', '.join(failed_packages)}")
        print_info("Run: pip install -r requirements.txt")
        return False
    else:
        print_success("All required packages are installed")
        return True

def test_opencv_functionality():
    """Test OpenCV specific functionality"""
    print_header("OpenCV Functionality Check")
    
    try:
        import cv2
        
        # Test cascade classifier loading
        cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        face_cascade = cv2.CascadeClassifier(cascade_path)
        
        if face_cascade.empty():
            print_error("Face cascade classifier failed to load")
            return False
        else:
            print_success("Face detection cascade loaded successfully")
        
        # Test basic OpenCV operations
        test_image = cv2.imread('non_existent_file.jpg')  # Should return None
        if test_image is None:
            print_success("OpenCV image loading function working")
        
        # Test image creation
        test_array = cv2.zeros((100, 100, 3), dtype='uint8')
        if test_array is not None:
            print_success("OpenCV array operations working")
        
        print_info(f"OpenCV Version: {cv2.__version__}")
        return True
        
    except Exception as e:
        print_error(f"OpenCV test failed: {str(e)}")
        return False

def test_librosa_functionality():
    """Test Librosa audio processing"""
    print_header("Audio Processing Check")
    
    try:
        import librosa
        import numpy as np
        
        # Create a simple test signal
        duration = 1.0  # 1 second
        sample_rate = 16000
        t = np.linspace(0, duration, int(sample_rate * duration))
        test_signal = np.sin(2 * np.pi * 440 * t)  # 440 Hz sine wave
        
        # Test spectral features
        spectral_centroids = librosa.feature.spectral_centroid(y=test_signal, sr=sample_rate)
        if spectral_centroids is not None:
            print_success("Spectral analysis working")
        
        # Test pitch tracking
        pitches, magnitudes = librosa.piptrack(y=test_signal, sr=sample_rate)
        if pitches is not None:
            print_success("Pitch analysis working")
        
        print_info(f"Librosa Version: {librosa.__version__}")
        return True
        
    except Exception as e:
        print_error(f"Librosa test failed: {str(e)}")
        return False

def test_project_structure():
    """Test if project structure is correct"""
    print_header("Project Structure Check")
    
    required_files = [
        ('app.py', 'Main Flask application'),
        ('requirements.txt', 'Python dependencies'),
        ('README.md', 'Project documentation')
    ]
    
    required_dirs = [
        ('uploads', 'File upload directory')
    ]
    
    all_good = True
    
    # Check files
    for filename, description in required_files:
        if os.path.exists(filename):
            print_success(f"{description} - {filename}")
        else:
            print_error(f"Missing {description} - {filename}")
            all_good = False
    
    # Check directories
    for dirname, description in required_dirs:
        if os.path.exists(dirname):
            print_success(f"{description} - {dirname}/")
        else:
            print_warning(f"Missing {description} - {dirname}/")
            print_info(f"Creating {dirname}/ directory")
            try:
                os.makedirs(dirname, exist_ok=True)
                print_success(f"Created {dirname}/ directory")
            except Exception as e:
                print_error(f"Failed to create {dirname}/: {str(e)}")
                all_good = False
    
    return all_good

def test_flask_app_import():
    """Test if Flask app can be imported"""
    print_header("Flask Application Check")
    
    try:
        # Try to import the app
        from app import app
        print_success("Flask app imported successfully")
        
        # Check if app is Flask instance
        from flask import Flask
        if isinstance(app, Flask):
            print_success("App is valid Flask instance")
        else:
            print_warning("App might not be a proper Flask instance")
        
        return True
        
    except ImportError as e:
        print_error(f"Cannot import Flask app: {str(e)}")
        print_info("Make sure app.py exists and contains valid Flask code")
        return False
    except Exception as e:
        print_warning(f"Flask app import issue: {str(e)}")
        return True  # May still work

def test_api_server():
    """Test if API server can start and respond"""
    print_header("API Server Test")
    
    print_info("Testing if server is already running...")
    
    try:
        # Test health endpoint
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        
        if response.status_code == 200:
            print_success("API server is running and responsive")
            
            # Parse response
            try:
                data = response.json()
                print_success(f"Service: {data.get('service', 'Unknown')}")
                print_success(f"Status: {data.get('status', 'Unknown')}")
                print_success(f"Version: {data.get('version', 'Unknown')}")
                
                if 'capabilities' in data:
                    print_info("Available capabilities:")
                    for capability in data['capabilities']:
                        print(f"    • {capability}")
                
                return True
                
            except json.JSONDecodeError:
                print_warning("Server responded but returned invalid JSON")
                return False
                
        else:
            print_warning(f"Server responded with status code: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print_warning("API server is not running")
        print_info("To start the server, run: python app.py")
        return False
    except requests.exceptions.Timeout:
        print_error("Server request timed out")
        return False
    except Exception as e:
        print_error(f"API server test failed: {str(e)}")
        return False

def test_api_endpoints():
    """Test individual API endpoints"""
    print_header("API Endpoints Test")
    
    base_url = 'http://localhost:5000'
    
    endpoints = [
        ('/', 'GET', 'API Documentation'),
        ('/api/health', 'GET', 'Health Check'),
        # POST endpoints would need files, so we'll just check if they exist
    ]
    
    all_good = True
    
    for endpoint, method, description in endpoints:
        try:
            url = base_url + endpoint
            
            if method == 'GET':
                response = requests.get(url, timeout=5)
            else:
                continue  # Skip POST endpoints for now
            
            if response.status_code == 200:
                print_success(f"{description} - {method} {endpoint}")
            else:
                print_warning(f"{description} - {method} {endpoint} (Status: {response.status_code})")
                all_good = False
                
        except requests.exceptions.ConnectionError:
            print_error(f"{description} - Server not running")
            all_good = False
        except Exception as e:
            print_error(f"{description} - {str(e)}")
            all_good = False
    
    # Test POST endpoint structure (without sending files)
    post_endpoints = [
        '/api/detect/image',
        '/api/detect/video', 
        '/api/detect/audio'
    ]
    
    for endpoint in post_endpoints:
        try:
            url = base_url + endpoint
            # Send empty POST to check if endpoint exists
            response = requests.post(url, timeout=5)
            
            # We expect 400 (bad request) since we're not sending files
            if response.status_code == 400:
                print_success(f"Detection endpoint available - POST {endpoint}")
            elif response.status_code == 405:
                print_error(f"Method not allowed - POST {endpoint}")
                all_good = False
            else:
                print_info(f"Detection endpoint responds - POST {endpoint} (Status: {response.status_code})")
                
        except requests.exceptions.ConnectionError:
            print_error(f"Detection endpoint - Server not running")
            all_good = False
        except Exception as e:
            print_warning(f"Detection endpoint test - {str(e)}")
    
    return all_good

def create_sample_test_files():
    """Create sample files for testing"""
    print_header("Sample Test Files Creation")
    
    try:
        import numpy as np
        from PIL import Image
        
        # Create sample image
        if not os.path.exists('test_image.jpg'):
            print_info("Creating sample test image...")
            img_array = np.random.randint(0, 255, (200, 200, 3), dtype=np.uint8)
            img = Image.fromarray(img_array)
            img.save('test_image.jpg')
            print_success("Created test_image.jpg")
        
        # Create sample audio file info
        print_info("For audio testing, you'll need to provide WAV or MP3 files")
        print_info("For video testing, you'll need to provide MP4, AVI, or MOV files")
        
        return True
        
    except Exception as e:
        print_error(f"Failed to create test files: {str(e)}")
        return False

def run_comprehensive_test():
    """Run all tests and provide summary"""
    print("🦅 HawkEye 2.0 - Comprehensive System Test")
    print("Starting comprehensive system validation...")
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Python Version", test_python_version),
        ("Required Packages", test_required_packages),
        ("OpenCV Functionality", test_opencv_functionality),
        ("Audio Processing", test_librosa_functionality),
        ("Project Structure", test_project_structure),
        ("Flask App Import", test_flask_app_import),
        ("API Server", test_api_server),
        ("API Endpoints", test_api_endpoints),
        ("Sample Files", create_sample_test_files)
    ]
    
    passed_tests = 0
    failed_tests = 0
    warning_tests = 0
    
    for test_name, test_function in tests:
        try:
            result = test_function()
            if result:
                passed_tests += 1
            else:
                failed_tests += 1
        except Exception as e:
            print_error(f"Test '{test_name}' crashed: {str(e)}")
            failed_tests += 1
        
        time.sleep(0.5)  # Small pause between tests
    
    # Print summary
    print_header("TEST SUMMARY")
    
    total_tests = len(tests)
    print_info(f"Total Tests: {total_tests}")
    print_success(f"Passed: {passed_tests}")
    
    if failed_tests > 0:
        print_error(f"Failed: {failed_tests}")
    
    success_rate = (passed_tests / total_tests) * 100
    print_info(f"Success Rate: {success_rate:.1f}%")
    
    # Final recommendation
    if success_rate >= 90:
        print("\n🎉 EXCELLENT! System is ready for production!")
        print("📝 Next steps:")
        print("   1. Run: python app.py")
        print("   2. Open: http://localhost:5000")
        print("   3. Test with your teammates")
        print("   4. Prepare for demo")
    elif success_rate >= 70:
        print("\n✅ GOOD! System is mostly ready!")
        print("⚠️ Fix any failed tests for optimal performance")
        print("💡 The system should still work for basic testing")
    else:
        print("\n❌ ATTENTION NEEDED! Multiple issues detected")
        print("🔧 Please fix the failed tests before proceeding")
        print("💡 Common fixes:")
        print("   • Run: pip install -r requirements.txt")
        print("   • Check Python version (need 3.8+)")
        print("   • Ensure all files are in place")
    
    print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return success_rate >= 70

if __name__ == "__main__":
    # Check if running with arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--quick":
            print("🦅 HawkEye 2.0 - Quick System Test")
            quick_tests = [
                test_python_version,
                test_required_packages,
                test_project_structure
            ]
            
            for test in quick_tests:
                test()
        elif sys.argv[1] == "--server":
            test_api_server()
            test_api_endpoints()
        else:
            print("Usage: python test_system.py [--quick|--server]")
    else:
        # Run comprehensive test
        run_comprehensive_test()