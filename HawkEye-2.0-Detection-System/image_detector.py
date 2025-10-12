# Image Deepfake Detector
# Repository: hawkeye-image-detector
# Advanced AI-based image manipulation and deepfake detection system

"""
HawkEye 2.0 - Image Manipulation Detection Module
================================================

This module implements multiple advanced techniques to detect:
- Image manipulation and editing
- AI-generated/deepfake images
- Face swapping and morphing
- Digital alterations and forgeries

Author: [Your Name] - Team Innovators
Project: HawkEye 2.0
"""

import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
import os
import tempfile
from datetime import datetime
import json


class ImageDeepfakeDetector:
    """
    Advanced Image Manipulation Detection System
    
    Uses multiple detection techniques:
    1. Error Level Analysis (ELA)
    2. Face Consistency Analysis
    3. Noise Pattern Detection
    4. Compression Artifact Analysis
    5. Metadata Forensics
    """
    
    def __init__(self):
        """Initialize the detector with required models and cascades"""
        self.face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
        self.detection_threshold = 0.6
        
    def detect_manipulation(self, image_path):
        """
        Main detection function - analyzes image for manipulation
        
        Args:
            image_path (str): Path to the image file
            
        Returns:
            dict: Detection results with confidence scores
        """
        try:
            # Validate image
            if not self._validate_image(image_path):
                return {'error': 'Invalid image file'}
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return {'error': 'Could not load image'}
            
            print(f"🔍 Analyzing image: {os.path.basename(image_path)}")
            
            # Run all detection methods
            results = {}
            
            # 1. Error Level Analysis
            print("  📊 Running Error Level Analysis...")
            results['ela_score'] = self._error_level_analysis(image_path)
            
            # 2. Face Consistency Check
            print("  👤 Analyzing face consistency...")
            results['face_consistency'] = self._face_consistency_check(img)
            
            # 3. Noise Analysis
            print("  🔬 Examining noise patterns...")
            results['noise_analysis'] = self._noise_analysis(img)
            
            # 4. Compression Analysis
            print("  📐 Checking compression artifacts...")
            results['compression_analysis'] = self._compression_analysis(img)
            
            # 5. Metadata Analysis
            print("  🏷️ Analyzing metadata...")
            results['metadata_analysis'] = self._metadata_analysis(image_path)
            
            # Calculate overall confidence
            confidence = self._calculate_confidence(results)
            is_manipulated = confidence > self.detection_threshold
            
            # Prepare final result
            final_result = {
                'is_manipulated': is_manipulated,
                'confidence': round(confidence, 3),
                'risk_level': self._get_risk_level(confidence),
                'analysis_details': results,
                'recommendations': self._get_recommendations(confidence, results),
                'analysis_type': 'image',
                'timestamp': datetime.now().isoformat(),
                'file_info': self._get_file_info(image_path)
            }
            
            print(f"  ✅ Analysis complete - Confidence: {confidence:.3f}")
            return final_result
            
        except Exception as e:
            return {'error': f'Image analysis failed: {str(e)}'}
    
    def _error_level_analysis(self, image_path):
        """
        Error Level Analysis - Detects JPEG compression inconsistencies
        
        Theory: Manipulated areas will have different compression levels
        than the original image, creating detectable patterns.
        """
        try:
            # Open original image
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Create temporary compressed version
            temp_path = tempfile.mktemp(suffix='.jpg')
            img.save(temp_path, 'JPEG', quality=90)
            
            # Calculate pixel-wise difference
            original = Image.open(image_path).convert('RGB')
            compressed = Image.open(temp_path).convert('RGB')
            
            # Get difference image
            diff = ImageChops.difference(original, compressed)
            
            # Enhance the difference to make artifacts visible
            enhancer = ImageEnhance.Brightness(diff)
            enhanced = enhancer.enhance(10)  # Amplify differences
            
            # Calculate statistics
            extrema = enhanced.getextrema()
            max_diff = max([ex[1] for ex in extrema])
            
            # Clean up
            os.remove(temp_path)
            
            # Normalize score (0-1, higher = more suspicious)
            ela_score = min(max_diff / 255.0, 1.0)
            
            return {
                'score': ela_score,
                'interpretation': self._interpret_ela_score(ela_score),
                'method': 'Error Level Analysis'
            }
            
        except Exception as e:
            return {'score': 0.5, 'error': str(e), 'method': 'Error Level Analysis'}
    
    def _face_consistency_check(self, img):
        """
        Face Consistency Analysis - Detects face swapping and morphing
        
        Checks for:
        - Inconsistent lighting on faces vs background
        - Edge artifacts around face boundaries
        - Color inconsistencies between face and surrounding skin
        """
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            
            if len(faces) == 0:
                return {
                    'score': 0.2,
                    'faces_detected': 0,
                    'interpretation': 'No faces detected - cannot analyze face consistency',
                    'method': 'Face Consistency Analysis'
                }
            
            total_suspicious_score = 0
            face_details = []
            
            for i, (x, y, w, h) in enumerate(faces):
                face_region = img[y:y+h, x:x+w]
                
                # 1. Edge artifact detection
                edges = cv2.Canny(face_region, 50, 150)
                edge_density = np.sum(edges > 0) / (w * h)
                
                # 2. Color consistency check
                face_mean_color = np.mean(face_region, axis=(0, 1))
                
                # Get surrounding region for comparison
                padding = 20
                y1, y2 = max(0, y-padding), min(img.shape[0], y+h+padding)
                x1, x2 = max(0, x-padding), min(img.shape[1], x+w+padding)
                surrounding_region = img[y1:y2, x1:x2]
                surrounding_mean_color = np.mean(surrounding_region, axis=(0, 1))
                
                # Calculate color difference
                color_diff = np.linalg.norm(face_mean_color - surrounding_mean_color) / 255.0
                
                # 3. Lighting consistency
                face_brightness = np.mean(cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY))
                surrounding_brightness = np.mean(cv2.cvtColor(surrounding_region, cv2.COLOR_BGR2GRAY))
                lighting_diff = abs(face_brightness - surrounding_brightness) / 255.0
                
                # Calculate face-level suspicion score
                face_score = (edge_density + color_diff + lighting_diff) / 3
                total_suspicious_score += face_score
                
                face_details.append({
                    'face_id': i + 1,
                    'edge_density': round(edge_density, 3),
                    'color_difference': round(color_diff, 3),
                    'lighting_difference': round(lighting_diff, 3),
                    'face_score': round(face_score, 3)
                })
            
            avg_score = total_suspicious_score / len(faces)
            
            return {
                'score': min(avg_score, 1.0),
                'faces_detected': len(faces),
                'face_details': face_details,
                'interpretation': self._interpret_face_score(avg_score),
                'method': 'Face Consistency Analysis'
            }
            
        except Exception as e:
            return {'score': 0.5, 'error': str(e), 'method': 'Face Consistency Analysis'}
    
    def _noise_analysis(self, img):
        """
        Noise Pattern Analysis - Detects inconsistent noise patterns
        
        Theory: Natural images have consistent noise throughout.
        Manipulated regions often have different noise characteristics.
        """
        try:
            # Convert to grayscale for noise analysis
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Remove main image content to isolate noise
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            noise = cv2.subtract(gray, blurred)
            
            # Analyze noise in different regions
            h, w = noise.shape
            regions = [
                noise[0:h//2, 0:w//2],      # Top-left
                noise[0:h//2, w//2:w],      # Top-right
                noise[h//2:h, 0:w//2],      # Bottom-left
                noise[h//2:h, w//2:w]       # Bottom-right
            ]
            
            # Calculate noise statistics for each region
            region_stats = []
            for i, region in enumerate(regions):
                if region.size > 0:
                    noise_std = np.std(region)
                    noise_mean = np.mean(np.abs(region))
                    region_stats.append({'std': noise_std, 'mean': noise_mean})
            
            # Check for consistency across regions
            if region_stats:
                stds = [stat['std'] for stat in region_stats]
                means = [stat['mean'] for stat in region_stats]
                
                # Calculate coefficient of variation
                std_cv = np.std(stds) / np.mean(stds) if np.mean(stds) > 0 else 0
                mean_cv = np.std(means) / np.mean(means) if np.mean(means) > 0 else 0
                
                # Higher variation = more suspicious
                inconsistency_score = (std_cv + mean_cv) / 2
                
                return {
                    'score': min(inconsistency_score * 2, 1.0),  # Amplify for detection
                    'std_coefficient_variation': round(std_cv, 3),
                    'mean_coefficient_variation': round(mean_cv, 3),
                    'region_stats': region_stats,
                    'interpretation': self._interpret_noise_score(inconsistency_score),
                    'method': 'Noise Pattern Analysis'
                }
            else:
                return {'score': 0.5, 'error': 'Could not analyze noise', 'method': 'Noise Pattern Analysis'}
            
        except Exception as e:
            return {'score': 0.5, 'error': str(e), 'method': 'Noise Pattern Analysis'}
    
    def _compression_analysis(self, img):
        """
        Compression Artifact Analysis - Detects inconsistent JPEG compression
        
        Looks for 8x8 block artifacts that are inconsistent across the image
        """
        try:
            # Convert to YUV (JPEG compression works on Y channel)
            yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
            y_channel = yuv[:, :, 0]
            
            # Analyze 8x8 blocks for JPEG artifacts
            h, w = y_channel.shape
            block_scores = []
            
            for i in range(0, h - 8, 8):
                for j in range(0, w - 8, 8):
                    block = y_channel[i:i+8, j:j+8]
                    
                    # Calculate DCT (similar to JPEG compression)
                    block_float = np.float32(block)
                    dct = cv2.dct(block_float)
                    
                    # Analyze high-frequency components
                    high_freq = dct[4:, 4:]  # High frequency components
                    high_freq_energy = np.sum(high_freq ** 2)
                    
                    # Check for artificial boundaries (blocking artifacts)
                    if i > 0 and j > 0:
                        # Compare with adjacent blocks
                        top_block = y_channel[i-8:i, j:j+8]
                        left_block = y_channel[i:i+8, j-8:j]
                        
                        # Edge discontinuity
                        top_edge_diff = np.mean(np.abs(block[0, :] - top_block[-1, :]))
                        left_edge_diff = np.mean(np.abs(block[:, 0] - left_block[:, -1]))
                        
                        edge_score = (top_edge_diff + left_edge_diff) / 2
                        block_scores.append(edge_score)
            
            if block_scores:
                # Calculate inconsistency in compression artifacts
                compression_variance = np.var(block_scores)
                mean_artifact_strength = np.mean(block_scores)
                
                # Higher variance suggests manipulation
                suspicion_score = min(compression_variance / 100, 1.0)
                
                return {
                    'score': suspicion_score,
                    'compression_variance': round(compression_variance, 3),
                    'mean_artifact_strength': round(mean_artifact_strength, 3),
                    'blocks_analyzed': len(block_scores),
                    'interpretation': self._interpret_compression_score(suspicion_score),
                    'method': 'Compression Artifact Analysis'
                }
            else:
                return {'score': 0.5, 'method': 'Compression Artifact Analysis'}
            
        except Exception as e:
            return {'score': 0.5, 'error': str(e), 'method': 'Compression Artifact Analysis'}
    
    def _metadata_analysis(self, image_path):
        """
        Metadata Forensics - Analyzes image metadata for manipulation signs
        
        Checks for:
        - Missing EXIF data (common in AI-generated images)
        - Suspicious software signatures
        - Inconsistent timestamps
        """
        try:
            img = Image.open(image_path)
            metadata_score = 0.5  # Default neutral score
            metadata_info = {}
            
            # Check for EXIF data
            if hasattr(img, '_getexif') and img._getexif():
                exif_data = img._getexif()
                metadata_info['has_exif'] = True
                metadata_info['exif_tags_count'] = len(exif_data) if exif_data else 0
                
                # Images with rich EXIF data are less likely to be AI-generated
                if exif_data and len(exif_data) > 10:
                    metadata_score = 0.2  # Less suspicious
                else:
                    metadata_score = 0.6  # Somewhat suspicious
                    
                # Check for camera information
                if exif_data:
                    camera_make = exif_data.get(271)  # Make
                    camera_model = exif_data.get(272)  # Model
                    software = exif_data.get(305)  # Software
                    
                    metadata_info['camera_make'] = camera_make
                    metadata_info['camera_model'] = camera_model
                    metadata_info['software'] = software
                    
                    # Check for suspicious software signatures
                    if software and any(sus in str(software).lower() 
                                      for sus in ['photoshop', 'gimp', 'paint.net', 'ai', 'generated']):
                        metadata_score += 0.3
            else:
                metadata_info['has_exif'] = False
                metadata_score = 0.7  # More suspicious - no EXIF data
            
            # Check file format and quality indicators
            metadata_info['format'] = img.format
            metadata_info['mode'] = img.mode
            metadata_info['size'] = img.size
            
            return {
                'score': min(metadata_score, 1.0),
                'metadata_info': metadata_info,
                'interpretation': self._interpret_metadata_score(metadata_score),
                'method': 'Metadata Forensics'
            }
            
        except Exception as e:
            return {'score': 0.5, 'error': str(e), 'method': 'Metadata Forensics'}
    
    def _calculate_confidence(self, results):
        """Calculate weighted confidence score from all detection methods"""
        weights = {
            'ela_score': 0.25,
            'face_consistency': 0.30,
            'noise_analysis': 0.20,
            'compression_analysis': 0.15,
            'metadata_analysis': 0.10
        }
        
        confidence = 0
        total_weight = 0
        
        for method, weight in weights.items():
            if method in results and 'score' in results[method]:
                confidence += results[method]['score'] * weight
                total_weight += weight
        
        # Normalize by actual weights used
        if total_weight > 0:
            confidence = confidence / total_weight
        
        return min(confidence, 1.0)
    
    def _get_risk_level(self, confidence):
        """Convert confidence score to risk level"""
        if confidence < 0.3:
            return "LOW"
        elif confidence < 0.6:
            return "MEDIUM" 
        elif confidence < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _get_recommendations(self, confidence, results):
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        if confidence > 0.7:
            recommendations.append("🚨 High probability of manipulation detected")
            recommendations.append("🔍 Manual expert review recommended")
        elif confidence > 0.5:
            recommendations.append("⚠️ Moderate suspicion - additional verification suggested")
        else:
            recommendations.append("✅ Low probability of manipulation")
        
        # Method-specific recommendations
        if 'face_consistency' in results and results['face_consistency'].get('score', 0) > 0.7:
            recommendations.append("👤 Face region shows signs of manipulation")
        
        if 'ela_score' in results and results['ela_score'].get('score', 0) > 0.7:
            recommendations.append("📐 Compression inconsistencies detected")
        
        return recommendations
    
    def _get_file_info(self, image_path):
        """Get basic file information"""
        try:
            stat = os.stat(image_path)
            img = Image.open(image_path)
            
            return {
                'filename': os.path.basename(image_path),
                'size_bytes': stat.st_size,
                'size_mb': round(stat.st_size / (1024*1024), 2),
                'dimensions': img.size,
                'format': img.format,
                'mode': img.mode
            }
        except:
            return {'filename': os.path.basename(image_path)}
    
    def _validate_image(self, image_path):
        """Validate if file is a valid image"""
        try:
            img = Image.open(image_path)
            img.verify()
            return True
        except:
            return False
    
    # Interpretation methods
    def _interpret_ela_score(self, score):
        if score < 0.3:
            return "Consistent compression - likely authentic"
        elif score < 0.6:
            return "Some compression inconsistencies detected"
        else:
            return "Significant compression artifacts - possible manipulation"
    
    def _interpret_face_score(self, score):
        if score < 0.3:
            return "Face regions appear consistent with background"
        elif score < 0.6:
            return "Minor inconsistencies in face regions"
        else:
            return "Significant face inconsistencies - possible face swap/deepfake"
    
    def _interpret_noise_score(self, score):
        if score < 0.3:
            return "Uniform noise pattern - appears natural"
        elif score < 0.6:
            return "Some noise inconsistencies detected"
        else:
            return "Non-uniform noise suggests possible manipulation"
    
    def _interpret_compression_score(self, score):
        if score < 0.3:
            return "Consistent compression artifacts"
        elif score < 0.6:
            return "Some compression inconsistencies"
        else:
            return "Irregular compression patterns detected"
    
    def _interpret_metadata_score(self, score):
        if score < 0.3:
            return "Rich metadata suggests camera-captured image"
        elif score < 0.6:
            return "Limited metadata - could be processed"
        else:
            return "Missing/suspicious metadata - possibly generated/heavily edited"


def main():
    """Demo function showing how to use the detector"""
    print("🦅 HawkEye 2.0 - Image Deepfake Detector")
    print("=" * 50)
    
    detector = ImageDeepfakeDetector()
    
    # Example usage
    image_path = "test_image.jpg"  # Replace with actual image path
    
    if os.path.exists(image_path):
        result = detector.detect_manipulation(image_path)
        
        if 'error' not in result:
            print(f"\n📊 DETECTION RESULTS")
            print(f"Is Manipulated: {result['is_manipulated']}")
            print(f"Confidence: {result['confidence']:.3f}")
            print(f"Risk Level: {result['risk_level']}")
            
            print(f"\n🔍 DETAILED ANALYSIS:")
            for method, details in result['analysis_details'].items():
                if isinstance(details, dict) and 'score' in details:
                    print(f"  {details['method']}: {details['score']:.3f}")
                    if 'interpretation' in details:
                        print(f"    → {details['interpretation']}")
            
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in result['recommendations']:
                print(f"  {rec}")
        else:
            print(f"❌ Error: {result['error']}")
    else:
        print("⚠️ Please provide a valid image path to test the detector")
        print("💡 Example: detector.detect_manipulation('path/to/your/image.jpg')")


if __name__ == "__main__":
    main()