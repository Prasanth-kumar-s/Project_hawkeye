# Video Deepfake Detector
# Repository: hawkeye-video-detector
# Advanced AI-based video deepfake detection system

"""
HawkEye 2.0 - Video Deepfake Detection Module
=============================================

This module implements advanced techniques to detect:
- Video deepfakes and face swaps
- Temporal inconsistencies in manipulated videos
- Face morphing and reenactment attacks
- AI-generated video content
- Digital video forgeries

Author: [Your Name] - Team Innovators
Project: HawkEye 2.0
"""

import cv2
import numpy as np
import os
from datetime import datetime
import json
from collections import deque
import math


class VideoDeepfakeDetector:
    """
    Advanced Video Deepfake Detection System
    
    Detection Techniques:
    1. Frame-by-frame deepfake analysis
    2. Temporal consistency checking
    3. Face tracking stability analysis
    4. Optical flow anomaly detection
    5. Facial landmark consistency
    6. Blending artifact detection
    """
    
    def __init__(self):
        """Initialize the detector with required models and parameters"""
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
)
    
        self.eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_eye.xml'
        )
        
        # Detection parameters
        self.detection_threshold = 0.65
        self.frame_sample_rate = 5  # Analyze every 5th frame for efficiency
        self.max_frames_to_analyze = 100  # Maximum frames to process
        
        # Temporal tracking
        self.face_history = deque(maxlen=10)
        self.landmark_history = deque(maxlen=10)
        
    def detect_deepfake(self, video_path):
        """
        Main detection function - analyzes video for deepfake indicators
        
        Args:
            video_path (str): Path to the video file
            
        Returns:
            dict: Detection results with confidence scores
        """
        try:
            # Validate video
            if not self._validate_video(video_path):
                return {'error': 'Invalid video file'}
            
            # Open video
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return {'error': 'Could not open video file'}
            
            # Get video properties
            video_info = self._get_video_info(cap)
            print(f"🎬 Analyzing video: {os.path.basename(video_path)}")
            print(f"   📊 Duration: {video_info['duration']:.2f}s, FPS: {video_info['fps']}, Frames: {video_info['frame_count']}")
            
            # Initialize analysis results
            results = {
                'frame_analysis': [],
                'temporal_analysis': {},
                'face_tracking': {},
                'optical_flow': {},
                'landmark_consistency': {},
                'blending_artifacts': {}
            }
            
            # Analyze video frames
            frame_idx = 0
            analyzed_frames = 0
            prev_frame = None
            prev_gray = None
            
            while True:
                ret, frame = cap.read()
                if not ret or analyzed_frames >= self.max_frames_to_analyze:
                    break
                
                # Sample frames at specified rate
                if frame_idx % self.frame_sample_rate == 0:
                    print(f"  🔍 Analyzing frame {frame_idx}...")
                    
                    # Individual frame analysis
                    frame_result = self._analyze_frame(frame, frame_idx)
                    results['frame_analysis'].append(frame_result)
                    
                    # Temporal analysis (requires previous frame)
                    if prev_frame is not None:
                        temporal_result = self._temporal_analysis(prev_frame, frame, frame_idx)
                        if temporal_result:
                            if frame_idx not in results['temporal_analysis']:
                                results['temporal_analysis'][frame_idx] = []
                            results['temporal_analysis'][frame_idx].append(temporal_result)
                    
                    # Optical flow analysis
                    if prev_gray is not None:
                        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                        optical_flow_result = self._optical_flow_analysis(prev_gray, gray, frame_idx)
                        if optical_flow_result:
                            results['optical_flow'][frame_idx] = optical_flow_result
                        prev_gray = gray
                    else:
                        prev_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    
                    prev_frame = frame.copy()
                    analyzed_frames += 1
                
                frame_idx += 1
            
            cap.release()
            
            # Post-processing analysis
            print("  📈 Computing overall statistics...")
            
            # Face tracking consistency
            results['face_tracking'] = self._analyze_face_tracking_consistency(results['frame_analysis'])
            
            # Landmark consistency
            results['landmark_consistency'] = self._analyze_landmark_consistency(results['frame_analysis'])
            
            # Blending artifacts
            results['blending_artifacts'] = self._analyze_blending_artifacts(results['frame_analysis'])
            
            # Calculate overall confidence
            confidence = self._calculate_video_confidence(results)
            is_deepfake = confidence > self.detection_threshold
            
            # Prepare final result
            final_result = {
                'is_deepfake': is_deepfake,
                'confidence': round(confidence, 3),
                'risk_level': self._get_risk_level(confidence),
                'analysis_summary': self._generate_analysis_summary(results),
                'detailed_analysis': results,
                'recommendations': self._get_recommendations(confidence, results),
                'video_info': video_info,
                'analysis_type': 'video',
                'frames_analyzed': analyzed_frames,
                'timestamp': datetime.now().isoformat()
            }
            
            print(f"  ✅ Analysis complete - Confidence: {confidence:.3f}")
            return final_result
            
        except Exception as e:
            return {'error': f'Video analysis failed: {str(e)}'}
    
    def _analyze_frame(self, frame, frame_idx):
        """
        Analyze individual frame for deepfake indicators
        
        Detects:
        - Face quality and consistency
        - Facial feature alignments
        - Skin texture anomalies
        - Eye and mouth region inconsistencies
        """
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            
            frame_result = {
                'frame_idx': frame_idx,
                'faces_detected': len(faces),
                'face_analyses': [],
                'overall_frame_score': 0.0
            }
            
            if len(faces) == 0:
                frame_result['overall_frame_score'] = 0.3  # Neutral score for no faces
                return frame_result
            
            total_face_score = 0
            
            for i, (x, y, w, h) in enumerate(faces):
                face_analysis = self._analyze_face_region(frame, (x, y, w, h), frame_idx)
                frame_result['face_analyses'].append(face_analysis)
                total_face_score += face_analysis['face_score']
                
                # Store face for temporal tracking
                self.face_history.append({
                    'frame_idx': frame_idx,
                    'bbox': (x, y, w, h),
                    'center': (x + w//2, y + h//2),
                    'size': w * h
                })
            
            # Calculate overall frame score
            frame_result['overall_frame_score'] = total_face_score / len(faces)
            return frame_result
            
        except Exception as e:
            return {'frame_idx': frame_idx, 'error': str(e), 'overall_frame_score': 0.5}
    
    def _analyze_face_region(self, frame, face_bbox, frame_idx):
        """
        Detailed analysis of individual face region
        """
        x, y, w, h = face_bbox
        face_region = frame[y:y+h, x:x+w]
        face_gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
        
        analysis = {
            'bbox': face_bbox,
            'face_score': 0.0,
            'details': {}
        }
        
        # 1. Blur inconsistency detection
        blur_score = self._detect_blur_inconsistency(face_region, frame, face_bbox)
        analysis['details']['blur_inconsistency'] = blur_score
        
        # 2. Eye region analysis
        eye_score = self._analyze_eye_regions(face_region, face_gray)
        analysis['details']['eye_analysis'] = eye_score
        
        # 3. Mouth region analysis
        mouth_score = self._analyze_mouth_region(face_region, face_gray)
        analysis['details']['mouth_analysis'] = mouth_score
        
        # 4. Skin texture analysis
        texture_score = self._analyze_skin_texture(face_region)
        analysis['details']['skin_texture'] = texture_score
        
        # 5. Color consistency
        color_score = self._analyze_face_color_consistency(face_region, frame, face_bbox)
        analysis['details']['color_consistency'] = color_score
        
        # 6. Edge artifacts
        edge_score = self._detect_edge_artifacts(face_region)
        analysis['details']['edge_artifacts'] = edge_score
        
        # Calculate weighted face score
        weights = {
            'blur_inconsistency': 0.25,
            'eye_analysis': 0.20,
            'mouth_analysis': 0.15,
            'skin_texture': 0.15,
            'color_consistency': 0.15,
            'edge_artifacts': 0.10
        }
        
        face_score = 0
        for key, weight in weights.items():
            if key in analysis['details']:
                face_score += analysis['details'][key] * weight
        
        analysis['face_score'] = min(face_score, 1.0)
        return analysis
    
    def _detect_blur_inconsistency(self, face_region, full_frame, face_bbox):
        """Detect if face has different blur level than surroundings"""
        try:
            x, y, w, h = face_bbox
            
            # Calculate face blur
            face_gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
            face_blur = cv2.Laplacian(face_gray, cv2.CV_64F).var()
            
            # Calculate surrounding region blur
            padding = 20
            y1 = max(0, y - padding)
            y2 = min(full_frame.shape[0], y + h + padding)
            x1 = max(0, x - padding)
            x2 = min(full_frame.shape[1], x + w + padding)
            
            surrounding = full_frame[y1:y2, x1:x2]
            surrounding_gray = cv2.cvtColor(surrounding, cv2.COLOR_BGR2GRAY)
            surrounding_blur = cv2.Laplacian(surrounding_gray, cv2.CV_64F).var()
            
            # Calculate blur ratio
            if surrounding_blur > 0:
                blur_ratio = abs(face_blur - surrounding_blur) / surrounding_blur
                return min(blur_ratio / 50.0, 1.0)  # Normalize
            
            return 0.5
            
        except Exception:
            return 0.5
    
    def _analyze_eye_regions(self, face_region, face_gray):
        """Analyze eye regions for deepfake indicators"""
        try:
            eyes = self.eye_cascade.detectMultiScale(face_gray, 1.1, 3)
            
            if len(eyes) < 2:
                return 0.6  # Suspicious if can't detect both eyes
            
            eye_scores = []
            for (ex, ey, ew, eh) in eyes:
                eye_region = face_region[ey:ey+eh, ex:ex+ew]
                
                # Check eye symmetry and sharpness
                eye_gray = cv2.cvtColor(eye_region, cv2.COLOR_BGR2GRAY)
                eye_sharpness = cv2.Laplacian(eye_gray, cv2.CV_64F).var()
                
                # Detect pupil consistency
                circles = cv2.HoughCircles(eye_gray, cv2.HOUGH_GRADIENT, 1, 20,
                                         param1=50, param2=30, minRadius=5, maxRadius=15)
                
                pupil_score = 0.3 if circles is None else 0.1
                sharpness_score = min(eye_sharpness / 100, 1.0)
                
                eye_scores.append((pupil_score + sharpness_score) / 2)
            
            return np.mean(eye_scores)
            
        except Exception:
            return 0.5
    
    def _analyze_mouth_region(self, face_region, face_gray):
        """Analyze mouth region for manipulation artifacts"""
        try:
            h, w = face_gray.shape
            # Mouth is typically in lower third of face
            mouth_region = face_region[int(h*0.6):, int(w*0.2):int(w*0.8)]
            
            if mouth_region.size == 0:
                return 0.5
            
            mouth_gray = cv2.cvtColor(mouth_region, cv2.COLOR_BGR2GRAY)
            
            # Detect mouth opening/closing consistency
            mouth_edges = cv2.Canny(mouth_gray, 50, 150)
            edge_density = np.sum(mouth_edges > 0) / mouth_edges.size
            
            # Check for unnatural mouth shapes (common in deepfakes)
            contours, _ = cv2.findContours(mouth_edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            if contours:
                largest_contour = max(contours, key=cv2.contourArea)
                area = cv2.contourArea(largest_contour)
                perimeter = cv2.arcLength(largest_contour, True)
                
                if perimeter > 0:
                    circularity = 4 * math.pi * area / (perimeter * perimeter)
                    # Unnatural circularity suggests manipulation
                    return min(abs(circularity - 0.3) * 2, 1.0)
            
            return edge_density * 2  # Higher edge density can indicate artifacts
            
        except Exception:
            return 0.5
    
    def _analyze_skin_texture(self, face_region):
        """Analyze skin texture for artificial smoothness"""
        try:
            face_gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
            
            # Calculate local binary patterns (texture analysis)
            # Simplified version - check variance in local neighborhoods
            kernel = np.ones((5,5), np.float32) / 25
            smoothed = cv2.filter2D(face_gray, -1, kernel)
            texture_variance = cv2.subtract(face_gray, smoothed)
            
            # Calculate texture statistics
            texture_std = np.std(texture_variance)
            texture_mean = np.mean(np.abs(texture_variance))
            
            # Very low texture variance suggests artificial smoothing
            if texture_std < 5:  # Threshold for unnaturally smooth
                return min(1.0 - (texture_std / 5.0), 1.0)
            
            return 0.2  # Natural texture
            
        except Exception:
            return 0.5
    
    def _analyze_face_color_consistency(self, face_region, full_frame, face_bbox):
        """Check color consistency between face and neck/surrounding areas"""
        try:
            x, y, w, h = face_bbox
            
            # Get face color
            face_mean_color = np.mean(face_region.reshape(-1, 3), axis=0)
            
            # Get neck region (below face)
            neck_y1 = min(full_frame.shape[0], y + h)
            neck_y2 = min(full_frame.shape[0], y + h + h//3)
            neck_region = full_frame[neck_y1:neck_y2, x:x+w]
            
            if neck_region.size > 0:
                neck_mean_color = np.mean(neck_region.reshape(-1, 3), axis=0)
                color_diff = np.linalg.norm(face_mean_color - neck_mean_color)
                return min(color_diff / 100.0, 1.0)  # Normalize
            
            return 0.3
            
        except Exception:
            return 0.5
    
    def _detect_edge_artifacts(self, face_region):
        """Detect artificial edges around face boundary"""
        try:
            face_gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(face_gray, 50, 150)
            
            # Check edge density around face boundary
            h, w = edges.shape
            boundary_width = 5
            
            # Top, bottom, left, right boundaries
            top_edges = edges[:boundary_width, :]
            bottom_edges = edges[-boundary_width:, :]
            left_edges = edges[:, :boundary_width]
            right_edges = edges[:, -boundary_width:]
            
            boundary_edge_density = (
                np.sum(top_edges > 0) + np.sum(bottom_edges > 0) +
                np.sum(left_edges > 0) + np.sum(right_edges > 0)
            ) / (4 * boundary_width * max(h, w))
            
            # High boundary edge density suggests artificial boundaries
            return min(boundary_edge_density * 5, 1.0)
            
        except Exception:
            return 0.5
    
    def _temporal_analysis(self, prev_frame, curr_frame, frame_idx):
        """Analyze temporal consistency between consecutive frames"""
        try:
            # Convert to grayscale
            prev_gray = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
            curr_gray = cv2.cvtColor(curr_frame, cv2.COLOR_BGR2GRAY)
            
            # Calculate frame difference
            frame_diff = cv2.absdiff(prev_gray, curr_gray)
            diff_mean = np.mean(frame_diff)
            diff_std = np.std(frame_diff)
            
            # Detect faces in both frames
            prev_faces = self.face_cascade.detectMultiScale(prev_gray, 1.3, 5)
            curr_faces = self.face_cascade.detectMultiScale(curr_gray, 1.3, 5)
            
            # Face consistency check
            face_consistency_score = self._check_face_consistency(prev_faces, curr_faces)
            
            # Temporal smoothness (sudden changes are suspicious)
            temporal_score = min(diff_std / 20.0, 1.0)
            
            return {
                'frame_difference': {
                    'mean': float(diff_mean),
                    'std': float(diff_std)
                },
                'face_consistency': face_consistency_score,
                'temporal_smoothness': temporal_score,
                'overall_temporal_score': (face_consistency_score + temporal_score) / 2
            }
            
        except Exception:
            return None
    
    def _check_face_consistency(self, prev_faces, curr_faces):
        """Check consistency of face positions between frames"""
        try:
            if len(prev_faces) == 0 and len(curr_faces) == 0:
                return 0.1  # No faces in either frame - consistent
            
            if len(prev_faces) != len(curr_faces):
                return 0.8  # Face count changed - suspicious
            
            if len(prev_faces) == 0:
                return 0.3  # No faces detected
            
            # Calculate movement between corresponding faces
            total_movement = 0
            for prev_face, curr_face in zip(prev_faces, curr_faces):
                prev_center = (prev_face[0] + prev_face[2]//2, prev_face[1] + prev_face[3]//2)
                curr_center = (curr_face[0] + curr_face[2]//2, curr_face[1] + curr_face[3]//2)
                
                movement = np.sqrt((prev_center[0] - curr_center[0])**2 + 
                                 (prev_center[1] - curr_center[1])**2)
                total_movement += movement
            
            avg_movement = total_movement / len(prev_faces)
            
            # Excessive movement between frames is suspicious
            return min(avg_movement / 30.0, 1.0)
            
        except Exception:
            return 0.5
    
    def _optical_flow_analysis(self, prev_gray, curr_gray, frame_idx):
        """Analyze optical flow for unnatural motion patterns"""
        try:
            # Calculate optical flow using Lucas-Kanade method
            # Detect corner points in previous frame
            corners = cv2.goodFeaturesToTrack(prev_gray, maxCorners=100, qualityLevel=0.3, minDistance=7)
            
            if corners is None:
                return {'flow_score': 0.3, 'points_tracked': 0}
            
            # Calculate optical flow
            new_corners, status, error = cv2.calcOpticalFlowPyrLK(prev_gray, curr_gray, corners, None)
            
            # Select good points
            good_new = new_corners[status == 1]
            good_old = corners[status == 1]
            
            if len(good_new) < 10:
                return {'flow_score': 0.4, 'points_tracked': len(good_new)}
            
            # Calculate flow vectors
            flow_vectors = good_new - good_old
            flow_magnitudes = np.sqrt(flow_vectors[:, 0]**2 + flow_vectors[:, 1]**2)
            
            # Analyze flow consistency
            flow_mean = np.mean(flow_magnitudes)
            flow_std = np.std(flow_magnitudes)
            
            # Inconsistent flow patterns suggest manipulation
            if flow_mean > 0:
                flow_consistency = flow_std / flow_mean
                flow_score = min(flow_consistency / 2.0, 1.0)
            else:
                flow_score = 0.3
            
            return {
                'flow_score': flow_score,
                'points_tracked': len(good_new),
                'flow_statistics': {
                    'mean_magnitude': float(flow_mean),
                    'std_magnitude': float(flow_std),
                    'consistency_ratio': float(flow_consistency) if flow_mean > 0 else 0
                }
            }
            
        except Exception:
            return {'flow_score': 0.5, 'points_tracked': 0}
    
    def _analyze_face_tracking_consistency(self, frame_analyses):
        """Analyze consistency of face tracking across all frames"""
        try:
            face_positions = []
            face_sizes = []
            
            for frame_result in frame_analyses:
                if 'face_analyses' in frame_result:
                    for face_analysis in frame_result['face_analyses']:
                        if 'bbox' in face_analysis:
                            x, y, w, h = face_analysis['bbox']
                            center = (x + w//2, y + h//2)
                            size = w * h
                            
                            face_positions.append(center)
                            face_sizes.append(size)
            
            if len(face_positions) < 2:
                return {'tracking_score': 0.3, 'positions_analyzed': len(face_positions)}
            
            # Calculate position variance
            positions_array = np.array(face_positions)
            position_variance = np.var(positions_array, axis=0)
            avg_position_variance = np.mean(position_variance)
            
            # Calculate size variance
            size_variance = np.var(face_sizes) if face_sizes else 0
            avg_size = np.mean(face_sizes) if face_sizes else 1
            
            # Normalize variances
            position_score = min(avg_position_variance / 1000, 1.0)
            size_score = min(size_variance / (avg_size * 0.1), 1.0) if avg_size > 0 else 0.5
            
            tracking_score = (position_score + size_score) / 2
            
            return {
                'tracking_score': tracking_score,
                'positions_analyzed': len(face_positions),
                'position_variance': float(avg_position_variance),
                'size_variance': float(size_variance),
                'interpretation': self._interpret_tracking_score(tracking_score)
            }
            
        except Exception:
            return {'tracking_score': 0.5, 'positions_analyzed': 0}
    
    def _analyze_landmark_consistency(self, frame_analyses):
        """Analyze facial landmark consistency (simplified version)"""
        try:
            # This is a simplified landmark analysis
            # In a full implementation, you would use dlib or similar for precise landmarks
            
            eye_positions = []
            mouth_positions = []
            
            for frame_result in frame_analyses:
                if 'face_analyses' in frame_result:
                    for face_analysis in frame_result['face_analyses']:
                        if 'details' in face_analysis:
                            # Use eye and mouth analysis results as proxy for landmark consistency
                            eye_score = face_analysis['details'].get('eye_analysis', 0.5)
                            mouth_score = face_analysis['details'].get('mouth_analysis', 0.5)
                            
                            eye_positions.append(eye_score)
                            mouth_positions.append(mouth_score)
            
            if not eye_positions:
                return {'landmark_score': 0.3, 'landmarks_analyzed': 0}
            
            # Calculate consistency in eye and mouth analysis scores
            eye_variance = np.var(eye_positions)
            mouth_variance = np.var(mouth_positions)
            
            # High variance in landmark-related scores suggests inconsistency
            landmark_score = min((eye_variance + mouth_variance) / 2, 1.0)
            
            return {
                'landmark_score': landmark_score,
                'landmarks_analyzed': len(eye_positions),
                'eye_score_variance': float(eye_variance),
                'mouth_score_variance': float(mouth_variance),
                'interpretation': self._interpret_landmark_score(landmark_score)
            }
            
        except Exception:
            return {'landmark_score': 0.5, 'landmarks_analyzed': 0}
    
    def _analyze_blending_artifacts(self, frame_analyses):
        """Analyze blending artifacts across frames"""
        try:
            edge_scores = []
            blur_scores = []
            color_scores = []
            
            for frame_result in frame_analyses:
                if 'face_analyses' in frame_result:
                    for face_analysis in frame_result['face_analyses']:
                        if 'details' in face_analysis:
                            edge_score = face_analysis['details'].get('edge_artifacts', 0.5)
                            blur_score = face_analysis['details'].get('blur_inconsistency', 0.5)
                            color_score = face_analysis['details'].get('color_consistency', 0.5)
                            
                            edge_scores.append(edge_score)
                            blur_scores.append(blur_score)
                            color_scores.append(color_score)
            
            if not edge_scores:
                return {'blending_score': 0.3, 'artifacts_analyzed': 0}
            
            # Calculate average artifact scores
            avg_edge_score = np.mean(edge_scores)
            avg_blur_score = np.mean(blur_scores)
            avg_color_score = np.mean(color_scores)
            
            # Overall blending artifact score
            blending_score = (avg_edge_score + avg_blur_score + avg_color_score) / 3
            
            return {
                'blending_score': blending_score,
                'artifacts_analyzed': len(edge_scores),
                'average_scores': {
                    'edge_artifacts': float(avg_edge_score),
                    'blur_inconsistency': float(avg_blur_score),
                    'color_inconsistency': float(avg_color_score)
                },
                'interpretation': self._interpret_blending_score(blending_score)
            }
            
        except Exception:
            return {'blending_score': 0.5, 'artifacts_analyzed': 0}
    
    def _calculate_video_confidence(self, results):
        """Calculate overall confidence score from all analyses"""
        weights = {
            'frame_analysis': 0.30,
            'temporal_analysis': 0.25,
            'face_tracking': 0.20,
            'optical_flow': 0.10,
            'landmark_consistency': 0.10,
            'blending_artifacts': 0.05
        }
        
        confidence = 0
        total_weight = 0
        
        # Frame analysis score
        if results['frame_analysis']:
            frame_scores = [f.get('overall_frame_score', 0.5) for f in results['frame_analysis']]
            avg_frame_score = np.mean(frame_scores)
            confidence += avg_frame_score * weights['frame_analysis']
            total_weight += weights['frame_analysis']
        
        # Temporal analysis score
        if results['temporal_analysis']:
            temporal_scores = []
            for frame_data in results['temporal_analysis'].values():
                for temp_result in frame_data:
                    temporal_scores.append(temp_result.get('overall_temporal_score', 0.5))
            
            if temporal_scores:
                avg_temporal_score = np.mean(temporal_scores)
                confidence += avg_temporal_score * weights['temporal_analysis']
                total_weight += weights['temporal_analysis']
        
        # Face tracking score
        if 'tracking_score' in results['face_tracking']:
            confidence += results['face_tracking']['tracking_score'] * weights['face_tracking']
            total_weight += weights['face_tracking']
        
        # Optical flow score
        if results['optical_flow']:
            flow_scores = [f.get('flow_score', 0.5) for f in results['optical_flow'].values()]
            if flow_scores:
                avg_flow_score = np.mean(flow_scores)
                confidence += avg_flow_score * weights['optical_flow']
                total_weight += weights['optical_flow']
        
        # Landmark consistency score
        if 'landmark_score' in results['landmark_consistency']:
            confidence += results['landmark_consistency']['landmark_score'] * weights['landmark_consistency']
            total_weight += weights['landmark_consistency']
        
        # Blending artifacts score
        if 'blending_score' in results['blending_artifacts']:
            confidence += results['blending_artifacts']['blending_score'] * weights['blending_artifacts']
            total_weight += weights['blending_artifacts']
        
        # Normalize by actual weights used
        if total_weight > 0:
            confidence = confidence / total_weight
        
        return min(confidence, 1.0)
    
    def _generate_analysis_summary(self, results):
        """Generate human-readable analysis summary"""
        summary = {}
        
        # Frame analysis summary
        if results['frame_analysis']:
            frame_scores = [f.get('overall_frame_score', 0.5) for f in results['frame_analysis']]
            summary['frame_analysis'] = {
                'frames_analyzed': len(frame_scores),
                'average_score': round(np.mean(frame_scores), 3),
                'score_variance': round(np.var(frame_scores), 3),
                'suspicious_frames': sum(1 for score in frame_scores if score > 0.7)
            }
        
        # Temporal analysis summary
        temporal_scores = []
        if results['temporal_analysis']:
            for frame_data in results['temporal_analysis'].values():
                for temp_result in frame_data:
                    temporal_scores.append(temp_result.get('overall_temporal_score', 0.5))
        
        if temporal_scores:
            summary['temporal_analysis'] = {
                'temporal_checks': len(temporal_scores),
                'average_score': round(np.mean(temporal_scores), 3),
                'suspicious_transitions': sum(1 for score in temporal_scores if score > 0.7)
            }
        
        # Face tracking summary
        if 'tracking_score' in results['face_tracking']:
            summary['face_tracking'] = {
                'tracking_score': results['face_tracking']['tracking_score'],
                'positions_analyzed': results['face_tracking'].get('positions_analyzed', 0)
            }
        
        return summary
    
    def _get_risk_level(self, confidence):
        """Convert confidence score to risk level"""
        if confidence < 0.3:
            return "LOW"
        elif confidence < 0.65:
            return "MEDIUM" 
        elif confidence < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _get_recommendations(self, confidence, results):
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        if confidence > 0.75:
            recommendations.append("🚨 High probability of deepfake detected")
            recommendations.append("🔍 Urgent manual expert review required")
            recommendations.append("⚠️ Do not trust this video content")
        elif confidence > 0.65:
            recommendations.append("⚠️ Moderate to high suspicion of manipulation")
            recommendations.append("🔍 Additional verification strongly recommended")
        elif confidence > 0.4:
            recommendations.append("⚠️ Some suspicious indicators detected")
            recommendations.append("💡 Consider cross-referencing with other sources")
        else:
            recommendations.append("✅ Low probability of deepfake manipulation")
            recommendations.append("💡 Video appears authentic based on current analysis")
        
        # Specific recommendations based on analysis results
        if results.get('face_tracking', {}).get('tracking_score', 0) > 0.7:
            recommendations.append("👤 Face tracking inconsistencies detected")
        
        if results.get('blending_artifacts', {}).get('blending_score', 0) > 0.7:
            recommendations.append("🎭 Blending artifacts suggest face swapping")
        
        summary = results.get('analysis_summary', {})
        if summary.get('frame_analysis', {}).get('suspicious_frames', 0) > 3:
            recommendations.append("📽️ Multiple suspicious frames detected")
        
        return recommendations
    
    def _get_video_info(self, cap):
        """Extract video metadata and properties"""
        try:
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = int(cap.get(cv2.CAP_PROP_FPS))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            duration = frame_count / fps if fps > 0 else 0
            
            return {
                'frame_count': frame_count,
                'fps': fps,
                'duration': duration,
                'resolution': (width, height),
                'total_pixels': width * height
            }
        except:
            return {'frame_count': 0, 'fps': 0, 'duration': 0, 'resolution': (0, 0)}
    
    def _validate_video(self, video_path):
        """Validate if file is a valid video"""
        try:
            cap = cv2.VideoCapture(video_path)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                return ret and frame is not None
            return False
        except:
            return False
    
    # Interpretation methods
    def _interpret_tracking_score(self, score):
        if score < 0.3:
            return "Stable face tracking - appears natural"
        elif score < 0.6:
            return "Some tracking inconsistencies detected"
        else:
            return "Significant tracking anomalies - possible manipulation"
    
    def _interpret_landmark_score(self, score):
        if score < 0.3:
            return "Consistent facial landmarks"
        elif score < 0.6:
            return "Minor landmark inconsistencies"
        else:
            return "Major landmark variations - possible deepfake"
    
    def _interpret_blending_score(self, score):
        if score < 0.3:
            return "Minimal blending artifacts"
        elif score < 0.6:
            return "Some blending inconsistencies detected"
        else:
            return "Significant blending artifacts - likely manipulation"


# (Your full detector code up to the truncated part is assumed unchanged above this point)
# I only modified the final printing section and added the __main__ guard.

def main():
    """Demo function showing how to use the detector"""
    print("🦅 HawkEye 2.0 - Video Deepfake Detector")
    print("=" * 50)
    
    detector = VideoDeepfakeDetector()
    
    # Example usage
    video_path = "test_video.mp4"  # Replace with actual video path
    
    if os.path.exists(video_path):
        result = detector.detect_deepfake(video_path)
        
        if 'error' not in result:
            print(f"\n📊 DETECTION RESULTS")
            print(f"Is Deepfake: {result['is_deepfake']}")
            print(f"Confidence: {result['confidence']:.3f}")
            print(f"Risk Level: {result['risk_level']}")
            
            print(f"\n🎬 VIDEO INFO:")
            video_info = result['video_info']
            print(f"  Duration: {video_info['duration']:.2f}s")
            print(f"  FPS: {video_info['fps']}")
            print(f"  Resolution: {video_info['resolution']}")
            print(f"  Frames Analyzed: {result['frames_analyzed']}")
            
            print(f"\n🔍 ANALYSIS SUMMARY:")
            summary = result.get('analysis_summary', {})
            for analysis_type, details in summary.items():
                print(f"  {analysis_type.replace('_', ' ').title()}:")
                for key, value in details.items():
                    print(f"    {key}: {value}")
            
            # Print some additional top-level recommended info
            print("\n📝 Recommendations:")
            for rec in result.get('recommendations', []):
                print(f"  - {rec}")
            
            # Optionally show a short snippet of detailed analysis (avoid huge dumps)
            print("\n🧾 Short Detailed Analysis Overview:")
            da = result.get('detailed_analysis', {})
            print(f"  Frame analysis entries: {len(da.get('frame_analysis', []))}")
            if da.get('temporal_analysis'):
                print(f"  Temporal checks: {len(da['temporal_analysis'])}")
            if da.get('optical_flow'):
                print(f"  Optical flow entries: {len(da['optical_flow'])}")
            
        else:
            # Error returned by detector
            print("\n❌ Analysis failed:")
            print(f"  {result.get('error')}")
    else:
        print(f"❌ Video file not found at path: {video_path}")
        print("   Please update `video_path` variable in main() to point to a valid video file.")
        

if __name__ == "__main__":
    main()
