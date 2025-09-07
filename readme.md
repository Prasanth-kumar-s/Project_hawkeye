# Secure File Uploader

A modern, security-focused file upload application with drag-and-drop functionality, comprehensive file validation, and enhanced user experience features.

### Features

### Core Functionality
- **Drag-and-Drop Interface**: Intuitive file upload with visual feedback
- **Multi-File Support**: Upload multiple files simultaneously
- **Real-Time Progress**: Live upload progress tracking with animations
- **File Type Validation**: Comprehensive MIME type checking
- **Size Limitations**: Configurable file size limits by category
- **Security Hardening**: Advanced validation and malware pattern detection

### Security Features
- **Enhanced File Validation**: Multi-layer file format verification
- **Content Analysis**: Basic malware pattern detection
- **Input Sanitization**: XSS prevention and path traversal protection
- **Rate Limiting**: Spam upload prevention
- **Suspicious Filename Detection**: Automated threat pattern recognition

### User Experience
- **Visual Feedback**: Smooth animations and progress indicators
- **Error Handling**: Comprehensive error messages and recovery options
- **File Categories**: Organized upload areas for different file types
- **Upload History**: Previous uploads tracking with timestamps
- **Batch Operations**: Bulk file management capabilities

##  Technologies Used

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **File Handling**: HTML5 File API, Drag and Drop API
- **Security**: Client-side validation, MIME type verification
- **UI/UX**: Custom CSS animations, responsive design

##  Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v14.0 or higher) - [Download here](https://nodejs.org/)
- **npm** (comes with Node.js) or **yarn**
- **Git** - [Download here](https://git-scm.com/)
- **Modern web browser** (Chrome, Firefox, Safari, Edge)

##  Quick Start

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/Prasanth-kumar-s/Project_hawkeye.git

# Navigate to the project directory
cd Project_hawkeye
```

### Step 2: Install Dependencies

```bash
# Install project dependencies
npm install

# Or if you prefer yarn
yarn install
```

### Step 3: Start the Development Server

```bash
# Start the local development server
npm start

# Or with yarn
yarn start
```

The application will be available at `http://localhost:3000`

### Step 4: Test the Application

1. **Open your browser** and navigate to `http://localhost:3000`
2. **Test drag-and-drop**: Drag files from your computer to the upload area
3. **Test file selection**: Click the upload button to select files manually
4. **Verify validation**: Try uploading different file types and sizes
5. **Check security features**: Attempt to upload files with suspicious names or formats

##  Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Security Settings
MAX_FILE_SIZE=50MB
ALLOWED_FILE_TYPES=image,video,audio,document

# Rate Limiting
MAX_UPLOADS_PER_HOUR=100
```

### Application Configuration

The main configuration is located in `config/app.js`:

```javascript
module.exports = {
    server: {
        port: process.env.PORT || 3000,
        host: 'localhost'
    },
    upload: {
        maxFiles: 10,
        maxFileSize: 50 * 1024 * 1024, // 50MB
        allowedTypes: ['image', 'video', 'audio', 'document']
    },
    security: {
        enableMalwareCheck: true,
        suspiciousPatterns: ['script', 'exe', 'bat', 'cmd']
    }
};
```

## 📖 Usage Guide

### Basic File Upload

1. **Drag and Drop**: Simply drag files from your computer onto the upload area
2. **File Selection**: Click the "Choose Files" button to select files manually
3. **Progress Tracking**: Watch real-time upload progress with visual indicators
4. **Error Handling**: Review any validation errors and retry as needed

### File Type Categories

The application supports four main categories:

- **Images**: JPEG, PNG, GIF, WebP (up to 15MB)
- **Videos**: MP4, AVI, MOV, WebM (up to 100MB)
- **Audio**: MP3, WAV, M4A, OGG (up to 20MB)
- **Documents**: PDF, TXT, DOC (up to 10MB)

### Batch Operations

1. Select multiple files using Ctrl+Click (Windows) or Cmd+Click (Mac)
2. Use the batch action buttons for bulk operations
3. Monitor progress for all files simultaneously

##  Customization Guide

### Adding New File Types

Modify the allowed file types in `app.js`:

```javascript
// In app.js, modify allowedFileTypes
allowedFileTypes: {
    images: ["image/jpeg", "image/png", "image/gif", "image/webp"],
    videos: ["video/mp4", "video/avi", "video/mov", "video/webm"],
    audio: ["audio/mp3", "audio/wav", "audio/m4a", "audio/ogg"],
    documents: ["application/pdf", "text/plain", "application/msword"],
    // Add new category
    spreadsheets: ["application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]
}
```

### Adjusting File Size Limits

Customize size limits for different file categories:

```javascript
// Modify fileSizeLimits in app.js
fileSizeLimits: {
    images: 15 * 1024 * 1024,     // 15MB
    videos: 100 * 1024 * 1024,    // 100MB
    audio: 20 * 1024 * 1024,      // 20MB
    documents: 10 * 1024 * 1024,  // 10MB
    spreadsheets: 5 * 1024 * 1024 // 5MB
}
```

### Adding Custom Validation Rules

Implement additional security checks:

```javascript
// Add to validateFile method in app.js
validateFile(file) {
    // Existing validations...
    
    // Custom validation: Block suspicious filenames
    if (this.config.securityPatterns.suspiciousNames.some(name => 
        file.name.toLowerCase().includes(name))) {
        throw new Error('Suspicious filename detected');
    }
    
    // Custom validation: Check file structure
    if (file.name.includes('..') || file.name.includes('/')) {
        throw new Error('Invalid file path detected');
    }
    
    // Custom validation: File extension whitelist
    const allowedExtensions = ['.jpg', '.png', '.pdf', '.txt'];
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
    if (!allowedExtensions.includes(fileExtension)) {
        throw new Error('File extension not allowed');
    }
}
```

### Styling Customization

Modify the appearance in `styles/main.css`:

```css
/* Customize upload area appearance */
.upload-area {
    border: 2px dashed #007bff;
    border-radius: 10px;
    background: linear-gradient(135deg, #f8f9fa, #e9ecef);
    transition: all 0.3s ease;
}

.upload-area:hover {
    border-color: #0056b3;
    background: linear-gradient(135deg, #e3f2fd, #bbdefb);
}

/* Customize progress bar */
.progress-bar {
    background: linear-gradient(90deg, #28a745, #20c997);
    border-radius: 5px;
    animation: pulse 2s infinite;
}
```

##  Development Roadmap

###  Phase 1: Core Functionality (Completed)
- [x] File upload interface
- [x] Drag-and-drop support
- [x] File validation and security
- [x] Progress tracking
- [x] Error handling

###  Phase 2: Enhancements (In Progress)
- [x] Enhanced file preview system
- [x] Batch upload operations
- [x] Advanced security validation
- [ ] Integration with backend APIs
- [x] User authentication system

###  Phase 3: Integration (Planned)
- [ ] Connect to AI detection models
- [ ] Database integration for file metadata
- [x] Real-time notifications
- [ ] Admin dashboard connection
- [ ] Cloud storage integration (AWS S3, Google Cloud)

###  Phase 4: Advanced Features (Future)
- [ ] File compression and optimization
- [ ] Virus scanning integration
- [ ] Multi-language support
- [ ] Mobile app companion
- [ ] API rate limiting and analytics

##  Troubleshooting

### Common Issues

**File not uploading:**
- Check browser console for JavaScript errors
- Verify file meets size and type requirements
- Ensure local development server is running
- Check network connectivity and firewall settings

**Drag-and-drop not working:**
- Verify browser supports HTML5 drag-and-drop API
- Check if event listeners are properly attached
- Test with different file types and browsers
- Clear browser cache and restart the application

**Security validation failing:**
- Review file validation logic in `app.js`
- Check MIME type mapping configuration
- Verify security patterns are up to date
- Test with known good files first

**Performance issues:**
- Check file sizes against configured limits
- Monitor browser memory usage
- Reduce concurrent uploads if necessary
- Clear upload history periodically

### Debug Mode

Enable debug mode for detailed logging:

```javascript
// In app.js
const DEBUG_MODE = true;

if (DEBUG_MODE) {
    console.log('File validation details:', validationResult);
    console.log('Upload progress:', progressData);
}
```

### Browser Compatibility

| Browser | Version | Status |
|---------|---------|--------|
| Chrome  | 70+     | ✅ Full Support |
| Firefox | 65+     | ✅ Full Support |
| Safari  | 12+     | ✅ Full Support |
| Edge    | 79+     | ✅ Full Support |
| IE      | 11      | ⚠️ Limited Support |

##  Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Guidelines

- Follow ES6+ JavaScript standards
- Add comments for complex logic
- Include tests for new features
- Update documentation as needed
- Ensure cross-browser compatibility

### Code Style

```javascript
// Use meaningful variable names
const uploadedFiles = [];
const maxFileSizeInBytes = 10 * 1024 * 1024;

// Add JSDoc comments for functions
/**
 * Validates uploaded file against security rules
 * @param {File} file - The file to validate
 * @returns {boolean} - Validation result
 */
function validateFile(file) {
    // Implementation here
}

```
## Output Images 

Login Mechanism 

<img width="3839" height="2090" alt="Screenshot 2025-09-07 131424" src="https://github.com/user-attachments/assets/55c26577-512b-49ee-b558-6684f9bf870b" />

User Upload Dashboard

<img width="3793" height="1854" alt="Screenshot 2025-09-07 131405" src="https://github.com/user-attachments/assets/e54507c0-3f6b-409e-ab6c-a6c22ac09879" />


Post Processing




<img width="3840" height="2069" alt="Screenshot 2025-09-07 131115" src="https://github.com/user-attachments/assets/1d624bb5-6b3b-4c13-83b8-8db26b672188" />



##  Acknowledgments

- HTML5 File API documentation and examples
- Security best practices from OWASP
- UI/UX inspiration from modern file upload interfaces
- Community feedback and contributions

##  Support
For more information checkout : https://docs.google.com/document/d/1DVflTFx1OfJERn16g_u-Tb0KX5BiPBXH/edit?usp=drive_link&ouid=101172896786625623849&rtpof=true&sd=true

---



