from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import os
import base64
import json
import tempfile
from werkzeug.utils import secure_filename
import io
import secrets
import logging
import traceback
import shutil
import binascii
from datetime import datetime
import time # For unique filenames in batch
import visualization  # Add this import at the top with other imports
import hashlib

# Import your steganography module
try:
    import stegfile as stegfile
except ImportError:
    logging.error("ERROR: stegfile.py not found or contains import errors.")
    stegfile = None

app = Flask(__name__,
    template_folder='templates',
    static_folder='static')  # Use relative path for static folder
app.secret_key = secrets.token_hex(16)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Increase max content length for large image uploads
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 32MB limit (adjust as needed)

# Define application directories
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.environ.get('STEGO_BASE_DIR', 'D:/Stegnography Project/Stego-TESTING-11')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
STATIC_DIR = os.path.join(BASE_DIR, 'static') # Use the explicit path

# Create necessary directories if they don't exist
for directory in [OUTPUT_DIR, KEYS_DIR, STATIC_DIR]:
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            os.chmod(directory, 0o777) # More permissive for dev, adjust for production
        except OSError as e:
            logger.error(f"Could not create directory {directory}: {e}")


# --- Routes (Keep existing routes for single pages: /, /explanation, /demos, etc.) ---
@app.route('/')
def index():
    return render_template('index1.html')

# Serve static HTML pages directly
@app.route('/explanation')
def explanation():
    return send_from_directory(STATIC_DIR, 'Explanation.html')

@app.route('/demos')
def demos():
    return send_from_directory(STATIC_DIR, 'demos.html')

@app.route('/flowchart')
def flowchart():
    return send_from_directory(STATIC_DIR, 'flowchart.html')

@app.route('/resources')
def resources():
    return send_from_directory(STATIC_DIR, 'resources.html')

@app.route('/quiz')
def quiz():
    return send_from_directory(STATIC_DIR, 'quiz.html')

@app.route('/glossary')
def glossary():
    return send_from_directory(STATIC_DIR, 'glossary.html')

@app.route('/security-guide')
def security_guide():
    return send_from_directory(STATIC_DIR, 'security_guide.html')


@app.route('/api/generate_key', methods=['POST'])
def generate_key():
    # Keep existing key generation
    if not stegfile: return jsonify({'error': 'Steganography module not loaded'}), 500
    try:
        key = stegfile.generate_key()
        return jsonify({'key': key})
    except Exception as e:
        logger.error(f"Error generating key: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

# --- Single File Endpoints (Keep Existing) ---
@app.route('/api/hide_message', methods=['POST'])
def hide_message():
    # Keep existing single hide logic
    if not stegfile: return jsonify({'success': False, 'error': 'Steganography module not loaded'}), 500
    cover_path, output_path, final_saved_path, key_path = None, None, None, None
    try:
        data = request.json
        if 'coverImage' not in data or not data['coverImage']: return jsonify({'success': False, 'error': 'Cover image data missing'}), 400
        cover_image_data = data['coverImage'].split(',')[1]
        cover_image_bytes = base64.b64decode(cover_image_data)
        cover_fd, cover_path = tempfile.mkstemp(suffix='.png', dir=OUTPUT_DIR) # Use output dir for temp
        try:
            with os.fdopen(cover_fd, 'wb') as f: f.write(cover_image_bytes)
            message = data.get('message', '')
            key = data.get('key')
            if not key: return jsonify({'success': False, 'error': 'Encryption key required'}), 400
            use_aes = data.get('useAES', True)
            enhanced_bit = data.get('enhancedBit', True)
            adaptive_channel = data.get('adaptiveChannel', True)
            error_correction = data.get('errorCorrection', True)
            embed_key = data.get('embedKey', True)
            custom_output_path = data.get('outputPath', None)
            custom_key_path = data.get('keyPath', None)

            target_output_dir = os.path.dirname(custom_output_path) if custom_output_path else OUTPUT_DIR
            if not os.path.exists(target_output_dir): os.makedirs(target_output_dir, exist_ok=True)

            final_saved_path = custom_output_path if custom_output_path else os.path.join(OUTPUT_DIR, f"stego_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")

            key_saved = False
            if custom_key_path and key:
                key_dir = os.path.dirname(custom_key_path)
                if not os.path.exists(key_dir): os.makedirs(key_dir, exist_ok=True)
                with open(custom_key_path, 'w') as f: f.write(key)
                try: os.chmod(custom_key_path, 0o600)
                except OSError: pass # Ignore chmod errors on some systems like Windows
                key_path = custom_key_path
                key_saved = True

            output_fd, output_path = tempfile.mkstemp(suffix='.png', dir=OUTPUT_DIR)
            os.close(output_fd)

            result = stegfile.hide_message( cover_path, output_path, message, key, use_aes=use_aes, enhanced_bit=enhanced_bit, adaptive_channel=adaptive_channel, error_correction=error_correction, embed_key=embed_key )

            shutil.copy2(output_path, final_saved_path)

            with open(final_saved_path, 'rb') as f: output_image_bytes = f.read()
            output_image_base64 = base64.b64encode(output_image_bytes).decode('utf-8')
            metrics = { 'psnr': result.get('psnr', 0), 'ssim': result.get('ssim', 0), 'ber': min(max(result.get('ber', 1.0), 0), 1), 'capacity': max(result.get('capacity', 0), 0) }
            encrypted_data = result.get('encrypted_message', '')
            encrypted_key = result.get('encrypted_key', '')

            return jsonify({ 'success': True, 'outputImage': f'data:image/png;base64,{output_image_base64}', 'metrics': metrics, 'savedPath': final_saved_path, 'encryptedData': encrypted_data, 'encryptedKey': encrypted_key, 'keySaved': key_saved, 'keyPath': key_path })
        except Exception as e:
            logger.error(f"Error in hide_message processing: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'success': False, 'error': f"Hiding failed: {str(e)}"}), 500
        finally:
            if cover_path and os.path.exists(cover_path): os.remove(cover_path)
            if output_path and os.path.exists(output_path): os.remove(output_path)
    except Exception as e:
        logger.error(f"Error handling /api/hide_message request: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': f"Request error: {str(e)}"}), 400

@app.route('/api/extract_message', methods=['POST'])
def extract_message():
    # Keep existing single extract logic
    if not stegfile: return jsonify({'success': False, 'error': 'Steganography module not loaded'}), 500
    stego_path = None
    try:
        data = request.json
        if 'stegoImage' not in data or not data['stegoImage']: return jsonify({'success': False, 'error': 'Stego image data missing'}), 400
        stego_image_data = data['stegoImage'].split(',')[1]
        stego_image_bytes = base64.b64decode(stego_image_data)
        stego_fd, stego_path = tempfile.mkstemp(suffix='.png', dir=OUTPUT_DIR)
        try:
            with os.fdopen(stego_fd, 'wb') as f: f.write(stego_image_bytes)
            key = data.get('key')
            extract_key = data.get('extractKey', True)
            use_aes = data.get('useAES', True)
            return_raw = data.get('returnRawData', True)
            enhanced_bit = data.get('enhancedBit', True)
            adaptive_channel = data.get('adaptiveChannel', True)

            result = stegfile.extract_message( stego_path, key, use_aes=use_aes, enhanced_bit=enhanced_bit, adaptive_channel=adaptive_channel, return_raw=return_raw, extract_key=extract_key )

            if isinstance(result, dict):
                 is_error = result.get('message', '').startswith("ERROR:")
                 return jsonify({ 'success': not is_error, 'error': result.get('message') if is_error else None, 'message': result.get('message', ''), 'rawData': result.get('raw_data', ''), 'extractedKey': result.get('extracted_key', ''), 'rawKeyData': result.get('raw_key_data', '') })
            else: # Handle legacy string return
                 is_error = isinstance(result, str) and result.startswith("ERROR:")
                 return jsonify({ 'success': not is_error, 'error': result if is_error else None, 'message': result if isinstance(result, str) else '', 'rawData': result if not use_aes and isinstance(result, str) and not is_error else '', 'extractedKey': '', 'rawKeyData': '' })
        except Exception as e:
            logger.error(f"Error in extract_message processing: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'success': False, 'error': f"Extraction failed: {str(e)}"}), 500
        finally:
            if stego_path and os.path.exists(stego_path): os.remove(stego_path)
    except Exception as e:
        logger.error(f"Error handling /api/extract_message request: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': f"Request error: {str(e)}"}), 400

# --- Directory Browsing (Keep Existing) ---
@app.route('/api/get_system_directories', methods=['GET'])
def get_system_directories():
    # Keep existing logic
    try:
        allowed_directories = [
            {'path': os.path.normpath(BASE_DIR), 'name': 'Project Root', 'icon': 'home'},
            {'path': os.path.normpath(OUTPUT_DIR), 'name': 'Output Files', 'icon': 'folder-open'},
            {'path': os.path.normpath(KEYS_DIR), 'name': 'Saved Keys', 'icon': 'key'},
        ]
        existing_dirs = [d for d in allowed_directories if os.path.isdir(d['path'])]
        return jsonify({'success': True, 'directories': existing_dirs})
    except Exception as e:
        logger.error(f"Error getting system directories: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/browse_directory', methods=['POST'])
def browse_directory():
    # Keep existing logic
    try:
        data = request.json
        requested_path = data.get('path')
        if not requested_path: return jsonify({'success': False, 'error': 'No path provided'}), 400
        requested_path = os.path.normpath(requested_path)
        allowed_roots = [ os.path.normpath(BASE_DIR) ] # Restrict to base dir
        allowed_access = False
        for root in allowed_roots:
            # Use os.path.realpath to resolve symlinks before checking common path
            real_root = os.path.realpath(root)
            real_requested = os.path.realpath(requested_path)
            if os.path.commonpath([real_root, real_requested]) == real_root:
                allowed_access = True
                break
        if not allowed_access: return jsonify({'success': False, 'error': 'Access restricted'}), 403
        if not os.path.exists(requested_path) or not os.path.isdir(requested_path): return jsonify({'success': False, 'error': 'Directory not found or inaccessible'}), 404

        directories = []
        try:
            for item in os.listdir(requested_path):
                item_path = os.path.join(requested_path, item)
                if os.path.isdir(item_path):
                    directories.append({'name': item, 'type': 'dir', 'path': os.path.normpath(item_path)})
        except PermissionError: return jsonify({'success': False, 'error': 'Permission denied'}), 403
        directories.sort(key=lambda x: x['name'].lower())
        parent_path = os.path.dirname(requested_path)
        real_parent = os.path.realpath(parent_path)
        can_go_up = any(os.path.commonpath([os.path.realpath(r), real_parent]) == os.path.realpath(r) for r in allowed_roots) and real_parent != os.path.realpath(requested_path)

        return jsonify({'success': True, 'path': requested_path, 'parent': os.path.normpath(parent_path) if can_go_up else None, 'directories': directories })
    except Exception as e:
        logger.error(f"Error browsing directory: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500


# --- Placeholder (Keep Existing) ---
@app.route('/api/placeholder/<width>/<height>')
def placeholder(width, height):
     # Keep existing placeholder logic
    try: from PIL import Image, ImageDraw
    except ImportError: pixel = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII='); return send_file(io.BytesIO(pixel), mimetype='image/png')
    try:
        w, h = int(width), int(height)
        if not (0 < w <= 2000 and 0 < h <= 2000): raise ValueError("Invalid dimensions")
        img = Image.new('RGB', (w, h), color=(45, 52, 54)); d = ImageDraw.Draw(img)
        text = "No Image"; text_x = max(10, w // 2 - len(text) * 3); text_y = max(10, h // 2 - 5)
        d.text((text_x, text_y), text, fill=(200, 200, 200)); img_io = io.BytesIO()
        img.save(img_io, 'PNG'); img_io.seek(0); return send_file(img_io, mimetype='image/png')
    except ValueError as e: return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e: logger.error(f"Error generating placeholder: {e}"); return jsonify({'success': False, 'error': 'Placeholder error'}), 500


# --- NEW BATCH PROCESSING ENDPOINTS ---

# Inside app12.py

# --- NEW BATCH PROCESSING ENDPOINTS ---

# Inside app12.py

@app.route('/api/batch_hide', methods=['POST'])
def batch_hide():
    if not stegfile:
        return jsonify({'success': False, 'error': 'Steganography module not loaded'}), 500

    results = []
    temp_files_to_clean = []

    try:
        # Get common parameters from form data
        message = request.form.get('message', '')
        key = request.form.get('key') # Expecting a hex string
        output_directory = request.form.get('outputDirectory', OUTPUT_DIR) # Use provided or default
        use_aes = request.form.get('useAES') == 'true'
        enhanced_bit = request.form.get('enhancedBit') == 'true'
        adaptive_channel = request.form.get('adaptiveChannel') == 'true'
        error_correction = request.form.get('errorCorrection') == 'true'
        embed_key = request.form.get('embedKey') == 'true'

        if not key:
            return jsonify({'success': False, 'error': 'Encryption key is required for batch hide'}), 400
        if not os.path.isdir(output_directory):
            try:
                os.makedirs(output_directory, exist_ok=True)
                os.chmod(output_directory, 0o777) # Ensure writable
            except OSError as e:
                 return jsonify({'success': False, 'error': f"Cannot create output directory: {output_directory} - {e}"}), 400
        # Ensure KEYS_DIR exists for saving keys
        if not os.path.exists(KEYS_DIR):
             try:
                 os.makedirs(KEYS_DIR, exist_ok=True)
                 os.chmod(KEYS_DIR, 0o777) # Ensure writable
             except OSError as e:
                  logger.warning(f"Could not create keys directory {KEYS_DIR}: {e}. Keys may not be saved.")


        # Get uploaded files
        cover_files = request.files.getlist('coverImages')
        if not cover_files:
            return jsonify({'success': False, 'error': 'No cover images provided for batch processing'}), 400

        logger.info(f"Starting batch hide for {len(cover_files)} images.")

        # Process each file
        for cover_file in cover_files:
            original_filename = secure_filename(cover_file.filename)
            file_result = {
                'filename': original_filename,
                'success': False,
                'error': None,
                'outputPath': None,
                'metrics': None,
                'message': message, # Include input message
                'key': key,       # Include key used
                'encryptedData': '',
                'encryptedKey': '',
                'keySavePath': None # Initialize key save path
            }
            cover_path = None
            output_path = None
            key_save_path = None # Define here for cleanup check

            try:
                # Save cover temporarily
                _, cover_extension = os.path.splitext(original_filename)
                # Use a unique temp name structure to avoid collisions even more reliably
                temp_prefix = f"cover_{secrets.token_hex(4)}_"
                cover_fd, cover_path = tempfile.mkstemp(prefix=temp_prefix, suffix=f"{cover_extension}", dir=OUTPUT_DIR)
                os.close(cover_fd)
                cover_file.save(cover_path)
                temp_files_to_clean.append(cover_path)
                logger.debug(f"Saved temp cover: {cover_path}")

                # Add file size after the file is saved
                file_result['file_size'] = os.path.getsize(cover_path) / 1024  # Add file size in KB

                # Define final output path components
                base_name, _ = os.path.splitext(original_filename)
                unique_suffix = secrets.token_hex(3) # Slightly shorter suffix
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

                # Stego image filename
                output_filename = f"{base_name}_stego_{timestamp}_{unique_suffix}.png" # Force PNG output
                final_output_path = os.path.join(output_directory, output_filename)

                # Corresponding key filename
                key_filename = f"{base_name}_stego_{timestamp}_{unique_suffix}.key"
                key_save_path = os.path.join(KEYS_DIR, key_filename) # Use defined KEYS_DIR

                # Create temporary path for stegfile output
                output_fd, output_path = tempfile.mkstemp(prefix=f"stego_{secrets.token_hex(4)}_", suffix=".png", dir=OUTPUT_DIR)
                os.close(output_fd)
                temp_files_to_clean.append(output_path)
                logger.debug(f"Created temp output path: {output_path}")

                # Call core function
                steg_result = stegfile.hide_message(
                    cover_path, output_path, message, key,
                    use_aes=use_aes, enhanced_bit=enhanced_bit, adaptive_channel=adaptive_channel,
                    error_correction=error_correction, embed_key=embed_key
                )

                # Check if steg_result indicates success
                if isinstance(steg_result, dict) and 'psnr' in steg_result:
                    # Copy temp result to final location
                    shutil.copy2(output_path, final_output_path)
                    file_result['success'] = True
                    file_result['outputPath'] = final_output_path
                    file_result['metrics'] = {
                        'psnr': steg_result.get('psnr', 0), 
                        'ssim': steg_result.get('ssim', 0),
                        'ber': steg_result.get('ber', 1.0), 
                        'capacity': steg_result.get('capacity', 0)
                    }
                    # Add metrics as top-level properties for easier graph generation
                    file_result['psnr'] = steg_result.get('psnr', 0)
                    file_result['ssim'] = steg_result.get('ssim', 0)
                    file_result['ber'] = steg_result.get('ber', 1.0)
                    file_result['capacity'] = steg_result.get('capacity', 0)
                    file_result['encryptedData'] = steg_result.get('encrypted_message', '')
                    file_result['encryptedKey'] = steg_result.get('encrypted_key', '')

                    # --- Save the key file ---
                    try:
                        with open(key_save_path, 'w') as kf:
                            kf.write(key) # Write the original key string
                        # Set permissions (read/write for owner only) - may fail on Windows
                        try: os.chmod(key_save_path, 0o600)
                        except OSError: pass
                        file_result['keySavePath'] = key_save_path # Add path to result
                        logger.info(f"Saved key for {original_filename} to {key_save_path}")
                    except Exception as key_save_error:
                        logger.error(f"Failed to save key file {key_save_path}: {key_save_error}")
                        file_result['error'] = (file_result['error'] or "") + f" | Key save failed: {key_save_error}" # Append error
                    # --- End Key Saving ---

                    logger.info(f"Successfully processed: {original_filename}")
                else:
                    # Handle potential error message returned as a string or in a dict
                    error_message = str(steg_result.get('message', steg_result)) if isinstance(steg_result, dict) else str(steg_result)
                    file_result['error'] = error_message
                    logger.error(f"Failed to process {original_filename}: {error_message}")

            except Exception as e:
                error_msg = f"Error processing {original_filename}: {str(e)}"
                logger.error(error_msg + f"\n{traceback.format_exc()}")
                file_result['error'] = error_msg
            finally:
                results.append(file_result)
                # Clean up temp files for this specific image immediately after processing
                if cover_path and os.path.exists(cover_path):
                     try: os.remove(cover_path)
                     except OSError as e: logger.warning(f"Could not remove temp cover {cover_path}: {e}")
                if output_path and os.path.exists(output_path):
                     try: os.remove(output_path)
                     except OSError as e: logger.warning(f"Could not remove temp output {output_path}: {e}")


        logger.info(f"Batch hide finished. Processed {len(results)} files.")
        return jsonify({'success': True, 'results': results})

    except Exception as e:
        error_msg = f"Error handling batch hide request: {str(e)}"
        logger.error(error_msg + f"\n{traceback.format_exc()}")
        # Clean up any remaining temp files if global error occurs
        for f_path in temp_files_to_clean:
             if os.path.exists(f_path):
                 try: os.remove(f_path)
                 except OSError as e_clean: logger.warning(f"Could not cleanup {f_path}: {e_clean}")
        return jsonify({'success': False, 'error': error_msg, 'results': results}), 500

# (Keep the /api/batch_extract function as it was in the previous update)
# ...

@app.route('/api/batch_extract', methods=['POST'])
def batch_extract():
    if not stegfile:
        return jsonify({'success': False, 'error': 'Steganography module not loaded'}), 500

    results = []
    temp_files_to_clean = []

    try:
        # Get common parameters
        key = request.form.get('key') or None # Get key, default to None if empty
        use_aes = request.form.get('useAES') == 'true'
        enhanced_bit = request.form.get('enhancedBit') == 'true'
        adaptive_channel = request.form.get('adaptiveChannel') == 'true'
        extract_key = request.form.get('extractKey') == 'true'
        return_raw = request.form.get('returnRawData') == 'true'

        # Get uploaded files
        stego_files = request.files.getlist('stegoImages')
        if not stego_files:
            return jsonify({'success': False, 'error': 'No stego images provided for batch processing'}), 400

        logger.info(f"Starting batch extract for {len(stego_files)} images.")

        # Process each file
        for stego_file in stego_files:
            original_filename = secure_filename(stego_file.filename)
            file_result = {
                'filename': original_filename,
                'success': False,
                'error': None,
                'message': None,
                'extractedKey': None,
                'encryptedData': '', # Raw encrypted message
                'encryptedKey': ''   # Raw encrypted key
            }
            stego_path = None

            try:
                # Save stego image temporarily
                _, stego_extension = os.path.splitext(original_filename)
                stego_fd, stego_path = tempfile.mkstemp(suffix=f"{stego_extension}", dir=OUTPUT_DIR)
                os.close(stego_fd)
                stego_file.save(stego_path)
                temp_files_to_clean.append(stego_path)
                logger.debug(f"Saved temp stego: {stego_path}")

                # Call core extraction function
                extract_result = stegfile.extract_message(
                    stego_path, key,
                    use_aes=use_aes, enhanced_bit=enhanced_bit, adaptive_channel=adaptive_channel,
                    return_raw=return_raw, extract_key=extract_key
                )

                # Process the result dictionary from stegfile
                if isinstance(extract_result, dict):
                     is_error = extract_result.get('message', '').startswith("ERROR:")
                     file_result['success'] = not is_error
                     file_result['message'] = extract_result.get('message', '') # Decrypted message or error
                     file_result['extractedKey'] = extract_result.get('extracted_key')
                     file_result['error'] = extract_result.get('message') if is_error else None
                     # Get raw data if available
                     file_result['encryptedData'] = extract_result.get('raw_data', '')
                     file_result['encryptedKey'] = extract_result.get('raw_key_data', '')

                     if is_error: logger.error(f"Failed to process {original_filename}: {file_result['message']}")
                     else: logger.info(f"Successfully processed: {original_filename}")
                else: # Handle legacy string return (fallback)
                     is_error = isinstance(extract_result, str) and extract_result.startswith("ERROR:")
                     file_result['success'] = not is_error
                     file_result['message'] = extract_result if isinstance(extract_result, str) else ''
                     file_result['error'] = extract_result if is_error else None
                     file_result['encryptedData'] = '' # Cannot get raw data in legacy mode
                     file_result['encryptedKey'] = ''
                     if is_error: logger.error(f"Failed to process {original_filename}: {extract_result}")
                     else: logger.info(f"Successfully processed: {original_filename}")


            except Exception as e:
                error_msg = f"Error processing {original_filename}: {str(e)}"
                logger.error(error_msg + f"\n{traceback.format_exc()}")
                file_result['error'] = error_msg
                file_result['message'] = f"ERROR: {error_msg}" # Ensure message indicates error
            finally:
                results.append(file_result)
                # Clean up temp file
                if stego_path and os.path.exists(stego_path):
                     try: os.remove(stego_path)
                     except OSError as e: logger.warning(f"Could not remove temp stego {stego_path}: {e}")

        logger.info(f"Batch extract finished. Processed {len(results)} files.")
        return jsonify({'success': True, 'results': results})

    except Exception as e:
        error_msg = f"Error handling batch extract request: {str(e)}"
        logger.error(error_msg + f"\n{traceback.format_exc()}")
        # Clean up any remaining temp files
        for f_path in temp_files_to_clean:
             if os.path.exists(f_path):
                 try: os.remove(f_path)
                 except OSError as e_clean: logger.warning(f"Could not cleanup {f_path}: {e_clean}")
        return jsonify({'success': False, 'error': error_msg, 'results': results}), 500

def cleanup_old_graphs():
    """Clean up graph files older than 24 hours"""
    graphs_dir = os.path.join(STATIC_DIR, 'graphs')
    if not os.path.exists(graphs_dir):
        return
        
    max_age = 24 * 60 * 60  # 24 hours
    current_time = time.time()
    
    logger.info(f"Starting cleanup of old graphs in {graphs_dir}")
    cleaned = 0
    
    for filename in os.listdir(graphs_dir):
        if filename.startswith('cache_'):  # Only clean cached graphs
            filepath = os.path.join(graphs_dir, filename)
            try:
                if current_time - os.path.getmtime(filepath) > max_age:
                    if os.path.isdir(filepath):
                        shutil.rmtree(filepath)
                    else:
                        os.remove(filepath)
                    cleaned += 1
            except OSError as e:
                logger.warning(f"Failed to remove old graph {filepath}: {e}")
                
    if cleaned > 0:
        logger.info(f"Cleaned up {cleaned} old graph files/directories")

def get_cached_graphs(batch_results, graphs_dir):
    """Check if graphs are cached for the given batch results"""
    try:
        # Create cache key from sorted, serialized results
        cache_key = hashlib.md5(
            json.dumps(batch_results, sort_keys=True).encode()
        ).hexdigest()
        
        cache_path = os.path.join(graphs_dir, f'cache_{cache_key}')
        
        if os.path.exists(cache_path):
            # Check if all expected graphs exist in cache
            expected_graphs = ['scatter_plots.png', 
                             'multi_metric_line.png', 'radar_chart.png']
            cached_files = os.listdir(cache_path)
            
            if all(graph in cached_files for graph in expected_graphs):
                logger.info(f"Found valid graph cache: {cache_key}")
                return cache_key, [f'cache_{cache_key}/{graph}' for graph in expected_graphs]
                
        return cache_key, None
    except Exception as e:
        logger.error(f"Error checking graph cache: {e}")
        return None, None

def create_fallback_graph(error_message, output_dir):
    """Create a simple placeholder graph when main graph generation fails"""
    try:
        import matplotlib.pyplot as plt
        
        plt.figure(figsize=(8, 6))
        plt.text(0.5, 0.5, f'Graph generation failed:\n{error_message}',
                ha='center', va='center', wrap=True)
        plt.axis('off')
        output_path = os.path.join(output_dir, 'error_graph.png')
        
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Created fallback error graph at {output_path}")
        return 'error_graph.png'
    except Exception as e:
        logger.error(f"Failed to create fallback graph: {e}")
        return None

@app.route('/api/batch_performance_graphs', methods=['POST'])
def generate_batch_graphs():
    """Generate performance visualization graphs for batch processing results"""
    try:
        batch_results = request.json.get('results', [])
        logger.info(f"Received batch results for graph generation: {len(batch_results)} items")
        
        if not batch_results:
            logger.error("No results provided for graph generation")
            return jsonify({'success': False, 'error': 'No results provided'})
        
        # Create graphs directory in static folder
        graphs_dir = os.path.join(STATIC_DIR, 'graphs')
        os.makedirs(graphs_dir, exist_ok=True)
        
        # Run cleanup of old graphs
        cleanup_old_graphs()
        
        # Check cache first
        cache_key, cached_graphs = get_cached_graphs(batch_results, graphs_dir)
        if cached_graphs:
            logger.info("Returning cached graphs")
            return jsonify({
                'success': True,
                'graphs': [f'/static/graphs/{graph}' for graph in cached_graphs]
            })
        
        # Create cache directory for new graphs
        cache_dir = os.path.join(graphs_dir, f'cache_{cache_key}')
        os.makedirs(cache_dir, exist_ok=True)
        
        # Log sample of the data for debugging
        logger.info(f"Sample data: {json.dumps(batch_results[0], indent=2)}")
        
        try:
            # Generate graphs
            result = visualization.generate_all_graphs(batch_results, cache_dir)
            logger.info(f"Graph generation result: {result}")
            
            if result['success']:
                # Convert graph paths to URLs
                graph_urls = [f'/static/graphs/cache_{cache_key}/{graph}' for graph in result['graphs']]
                logger.info(f"Generated graph URLs: {graph_urls}")
                return jsonify({
                    'success': True,
                    'graphs': graph_urls
                })
            else:
                # If main graphs fail, create fallback error graph
                error_msg = result.get('error', 'Unknown error generating graphs')
                logger.error(f"Failed to generate graphs: {error_msg}")
                
                fallback_graph = create_fallback_graph(error_msg, cache_dir)
                if fallback_graph:
                    return jsonify({
                        'success': True,
                        'graphs': [f'/static/graphs/cache_{cache_key}/{fallback_graph}']
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': error_msg
                    })
        except Exception as e:
            # Clean up cache directory if generation fails
            try:
                shutil.rmtree(cache_dir)
            except OSError:
                pass
            raise e
            
    except Exception as e:
        logger.error(f"Error generating batch graphs: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)})

# --- Error Handlers (Keep Existing) ---
@app.errorhandler(404)
def not_found(error):
     if request.path.startswith('/api/'): return jsonify({'success': False, 'error': 'API endpoint not found'}), 404
     else: return "<h1>404 - Page Not Found</h1>", 404

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'success': False, 'error': 'File too large. Max size is 32MB.'}), 413 # Updated limit

@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {error}\n{traceback.format_exc()}")
    return jsonify({'success': False, 'error': 'Internal server error occurred'}), 500

# Add a route to serve graph images
@app.route('/static/graphs/<path:filename>')
def serve_graph(filename):
    """Serve graph images from the graphs directory"""
    return send_from_directory(os.path.join(STATIC_DIR, 'graphs'), filename)

if __name__ == '__main__':
    if not stegfile:
        print("\n" + "="*50 + "\n ERROR: Could not load 'stegfile.py'. \n Ensure the file exists and has no errors. \n Application might not function correctly. \n" + "="*50 + "\n")
    # Use host='0.0.0.0' to make accessible on network if needed
    app.run(debug=True, host='127.0.0.1', port=5002) # Run on different port, accessible on network