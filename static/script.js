document.addEventListener('DOMContentLoaded', function() {
    // === DOM Elements ===
    const themeToggle = document.getElementById('themeToggle');
    const logContainer = document.getElementById('logContainer');
    const notification = document.getElementById('notification');
  
    // --- Single Mode Elements ---
    const coverDropArea = document.getElementById('coverDropArea');
    const coverFileInput = document.getElementById('coverFileInput');
    const stegoDropArea = document.getElementById('stegoDropArea');
    const stegoFileInput = document.getElementById('stegoFileInput');
    const coverFileDisplay = document.getElementById('coverFileDisplay');
    const coverFilenameSpan = document.getElementById('coverFilename');
    const stegoFileDisplay = document.getElementById('stegoFileDisplay');
    const stegoFilenameSpan = document.getElementById('stegoFilename');
    const outputPath = document.getElementById('outputPath');
    const coverPreview = document.getElementById('coverPreview');
    const outputPreview = document.getElementById('outputPreview');
    const hideProgress = document.getElementById('hideProgress');
    const hideProgressBar = document.getElementById('hideProgressBar');
    const hideProgressText = document.getElementById('hideProgressText');
    const extractProgress = document.getElementById('extractProgress');
    const extractProgressBar = document.getElementById('extractProgressBar');
    const extractProgressText = document.getElementById('extractProgressText');
    const messageInput = document.getElementById('message');
    const extractedText = document.getElementById('extractedText');
    const encryptedMessage = document.getElementById('encryptedMessage');
    const encryptedExtracted = document.getElementById('encryptedExtracted');
    const encryptedKey = document.getElementById('encryptedKey');
    const extractedKey = document.getElementById('extractedKey');
    const rawEncryptedKey = document.getElementById('rawEncryptedKey');
    const psnrValue = document.getElementById('psnrValue');
    const ssimValue = document.getElementById('ssimValue');
    const berValue = document.getElementById('berValue');
    const capacityValue = document.getElementById('capacityValue');
    const psnrBar = document.getElementById('psnrBar');
    const ssimBar = document.getElementById('ssimBar');
    const berBar = document.getElementById('berBar');
    const capacityBar = document.getElementById('capacityBar');
    const hideMessageBtn = document.getElementById('hideMessage');
    const extractMessageBtn = document.getElementById('extractMessage');
    const browseOutputBtn = document.getElementById('browseOutput');
  
    // --- Key Management Elements ---
    const keyDisplayContainer = document.getElementById('keyDisplayContainer');
    const currentKey = document.getElementById('currentKey');
    const toggleKeyVisibility = document.getElementById('toggleKeyVisibility');
    const copyKey = document.getElementById('copyKey');
    const keyStatus = document.getElementById('keyStatus');
    const generateKeyBtn = document.getElementById('generateKey');
    const loadKeyBtn = document.getElementById('loadKey');
  
    // --- Visibility/Copy Buttons ---
    const copyEncrypted = document.getElementById('copyEncrypted');
    const copyEncryptedExtracted = document.getElementById('copyEncryptedExtracted');
    const copyEncryptedKey = document.getElementById('copyEncryptedKey');
    const copyExtractedKey = document.getElementById('copyExtractedKey');
    const copyRawKey = document.getElementById('copyRawKey');
    const toggleEncryptedVisibility = document.getElementById('toggleEncryptedVisibility');
    const toggleEncryptedExtractedVisibility = document.getElementById('toggleEncryptedExtractedVisibility');
    const toggleEncryptedKeyVisibility = document.getElementById('toggleEncryptedKeyVisibility');
    const toggleExtractedKeyVisibility = document.getElementById('toggleExtractedKeyVisibility');
    const toggleRawKeyVisibility = document.getElementById('toggleRawKeyVisibility');
  
    // --- Modal Elements ---
    const directoryModal = document.getElementById('directoryModal');
    const modalTitle = document.getElementById('modalTitle');
    const closeModal = document.getElementById('closeModal');
    const selectDirectory = document.getElementById('selectDirectory');
    const cancelDirectorySelect = document.getElementById('cancelDirectorySelect');
    const currentPathSpan = document.getElementById('currentPath');
    const directoryList = document.getElementById('directoryList');
  
    // --- Batch Processing Elements ---
    const batchCoverDropArea = document.getElementById('batchCoverDropArea');
    const batchCoverInput = document.getElementById('batchCoverInput');
    const batchCoverFileList = document.getElementById('batchCoverFileList');
    const batchCoverFileCount = document.getElementById('batchCoverFileCount');
    const clearBatchCoverFilesBtn = document.getElementById('clearBatchCoverFiles');
    const batchMessageInput = document.getElementById('batchMessage');
    const batchOutputPath = document.getElementById('batchOutputPath');
    const batchBrowseOutputBtn = document.getElementById('batchBrowseOutput');
    const startBatchHideBtn = document.getElementById('startBatchHide');
    const batchHideProgress = document.getElementById('batchHideProgress');
    const batchHideProgressBar = document.getElementById('batchHideProgressBar');
    const batchHideProgressText = document.getElementById('batchHideProgressText');
    const batchHideResultsContainer = document.getElementById('batchHideResultsContainer');
    const batchHideResultsBody = document.getElementById('batchHideResultsBody');
  
    const batchStegoDropArea = document.getElementById('batchStegoDropArea');
    const batchStegoInput = document.getElementById('batchStegoInput');
    const batchStegoFileList = document.getElementById('batchStegoFileList');
    const batchStegoFileCount = document.getElementById('batchStegoFileCount');
    const clearBatchStegoFilesBtn = document.getElementById('clearBatchStegoFiles');
    const startBatchExtractBtn = document.getElementById('startBatchExtract');
    const batchExtractProgress = document.getElementById('batchExtractProgress');
    const batchExtractProgressBar = document.getElementById('batchExtractProgressBar');
    const batchExtractProgressText = document.getElementById('batchExtractProgressText');
    const batchExtractResultsContainer = document.getElementById('batchExtractResultsContainer');
    const batchExtractResultsBody = document.getElementById('batchExtractResultsBody');
  
    // --- Tabs ---
    const batchGraphsCard = document.getElementById('batchGraphsCard');
    const batchGraphsContent = document.getElementById('batchGraphsContent');
    const graphSliderContainer = document.getElementById('graphSliderContainer');
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    const fullscreenGraphModal = document.getElementById('fullscreenGraphModal');
    const fullscreenGraphImage = document.getElementById('fullscreenGraphImage');
    const closeFullscreenGraphBtn = document.getElementById('closeFullscreenGraph');
  
    // === Global Variables ===
    let currentKeyValue = null;
    let coverImageData = null; // Base64 for single mode
    let stegoImageData = null; // Base64 for single mode
    let batchCoverFiles = []; // Array to hold batch cover File objects
    let batchStegoFiles = []; // Array to hold batch stego File objects
    let currentOutputDirectory = ''; // Will be set from default or browse
    let activeModalPurpose = null; // 'output', 'batchOutput'
    let originalCoverFilename = ''; // Store original filename for key/output naming
    let systemDirectories = []; // Store fetched system directories
    let lastBatchHideResults = []; // Store results for graph generation
  
    // Graph Slider State
    let graphSliderWrapper = null;
    let graphSlides = [];
    let graphPaginationDots = [];
    let currentGraphIndex = 0;
    let totalGraphSlides = 0;
    let currentActiveTabId = 'hideTabContent'; // Track the active tab
  
     const DEFAULT_PATHS = {
      baseDir: 'D:/Stegnography Project/Stego-TESTING-11', // *** ADJUST THIS PATH AS NEEDED ***
      outputDir: 'D:/Stegnography Project/Stego-TESTING-11/output', // *** ADJUST THIS PATH AS NEEDED ***
      keysDir: 'D:/Stegnography Project/Stego-TESTING-11/keys' // *** ADJUST THIS PATH AS NEEDED ***
    };
  
    // === Initialization ===
    function initApp() {
      addLog('Application initialized', 'info');
      // Set default output paths
      outputPath.value = DEFAULT_PATHS.outputDir;
      batchOutputPath.value = DEFAULT_PATHS.outputDir;
      currentOutputDirectory = DEFAULT_PATHS.outputDir;
  
      setupEventListeners();
      fetchSystemDirectories();
  
      // Theme setup
      const savedTheme = localStorage.getItem('theme');
      const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
      if (savedTheme === 'light' || (!savedTheme && prefersLight)) {
           document.body.classList.add('light-mode'); updateThemeButton(true);
      } else { updateThemeButton(false); }
  
      // Activate first tab
        batchGraphsCard.style.display = 'none';
        activateTab(tabButtons[0], tabButtons[0].dataset.tab);

        addLog('Ready.', 'info');
        setupFullscreenListeners();
    }
  
    // === Event Listeners Setup ===
    function setupEventListeners() {
      themeToggle.addEventListener('click', toggleTheme);
  
      // Tab switching
      tabButtons.forEach(button => {
        button.addEventListener('click', () => activateTab(button, button.dataset.tab));
      });
  
      // --- Single Mode File Handling ---
      setupDragDrop(coverDropArea, (files) => handleCoverImage(files[0]));
      coverFileInput.addEventListener('change', (e) => handleCoverImage(e.target.files[0]));
      coverDropArea.addEventListener('click', () => coverFileInput.click());
  
      setupDragDrop(stegoDropArea, (files) => handleStegoImage(files[0]));
      stegoFileInput.addEventListener('change', (e) => handleStegoImage(e.target.files[0]));
      stegoDropArea.addEventListener('click', () => stegoFileInput.click());
  
      browseOutputBtn.addEventListener('click', () => browseOutputDirectory('output'));
      batchBrowseOutputBtn.addEventListener('click', () => browseOutputDirectory('batchOutput')); // Corrected batch browse listener
  
      // Key Management
      generateKeyBtn.addEventListener('click', generateKey);
      loadKeyBtn.addEventListener('click', loadKey);
      toggleKeyVisibility.addEventListener('click', () => toggleInputVisibility(currentKey, toggleKeyVisibility));
      copyKey.addEventListener('click', () => copyToClipboard(currentKeyValue, 'Encryption key copied'));

      // Main Actions (Single Mode)
      hideMessageBtn.addEventListener('click', hideMessageAction);
      extractMessageBtn.addEventListener('click', extractMessageAction);

  
      // Textarea Actions
      setupVisibilityToggle(toggleEncryptedVisibility, encryptedMessage);
      setupVisibilityToggle(toggleEncryptedExtractedVisibility, encryptedExtracted);
      setupVisibilityToggle(toggleEncryptedKeyVisibility, encryptedKey);
      setupVisibilityToggle(toggleExtractedKeyVisibility, extractedKey);
      setupVisibilityToggle(toggleRawKeyVisibility, rawEncryptedKey);
      setupCopyButton(copyEncrypted, encryptedMessage);
      setupCopyButton(copyEncryptedExtracted, encryptedExtracted);
      setupCopyButton(copyEncryptedKey, encryptedKey);
      setupCopyButton(copyExtractedKey, extractedKey);
      setupCopyButton(copyRawKey, rawEncryptedKey);
  
      // --- Batch Mode File Handling ---
      setupDragDrop(batchCoverDropArea, handleBatchCoverFiles);
      batchCoverInput.addEventListener('change', (e) => handleBatchCoverFiles(e.target.files));
      batchCoverDropArea.addEventListener('click', () => batchCoverInput.click());
      clearBatchCoverFilesBtn.addEventListener('click', () => clearBatchFiles('cover'));
  
      setupDragDrop(batchStegoDropArea, handleBatchStegoFiles);
      batchStegoInput.addEventListener('change', (e) => handleBatchStegoFiles(e.target.files));
      batchStegoDropArea.addEventListener('click', () => batchStegoInput.click());
      clearBatchStegoFilesBtn.addEventListener('click', () => clearBatchFiles('stego'));
  
      // Batch Browse Button
     // batchBrowseOutputBtn.addEventListener('click', () => browseOutputDirectory('batchOutput'));
  
      // Batch Actions
      startBatchHideBtn.addEventListener('click', startBatchHideAction);
      startBatchExtractBtn.addEventListener('click', startBatchExtractAction);

  
      // Modal Handlers
      closeModal.addEventListener('click', closeDirectoryModal);
      cancelDirectorySelect.addEventListener('click', closeDirectoryModal);
      selectDirectory.addEventListener('click', selectCurrentDirectory);
      directoryModal.addEventListener('click', (e) => { if (e.target === directoryModal) closeDirectoryModal(); });
  
      // Graph Slider Event Listeners (delegated)
      graphSliderContainer.addEventListener('click', (e) => {
          if (e.target.closest('.slider-button.next')) {
              nextGraphSlide();
          } else if (e.target.closest('.slider-button.prev')) {
              prevGraphSlide();
          } else if (e.target.classList.contains('slider-dot')) {
              const index = parseInt(e.target.dataset.index);
              goToGraphSlide(index);
          }

          if (e.target.classList.contains('performance-graph') && e.target.classList.contains('loaded')) {
            openFullscreenGraph(e.target.src);
          }
      });
    }
  
    function setupFullscreenListeners() {
        closeFullscreenGraphBtn.addEventListener('click', closeFullscreenGraph);
        fullscreenGraphModal.addEventListener('click', (event) => {
            // Close only if the background overlay itself is clicked
            if (event.target === fullscreenGraphModal) {
                closeFullscreenGraph();
            }
        });
        // Add Escape key listener dynamically when opened
    }

    // === Helper Functions ===
    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
    function addLog(message, type = 'info') { const now = new Date(); const time = now.toTimeString().split(' ')[0]; const logEntry = document.createElement('div'); logEntry.className = 'log-entry'; const safeMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;"); logEntry.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-${type}">${safeMessage}</span>`; logContainer.appendChild(logEntry); logContainer.scrollTop = logContainer.scrollHeight; }
    function showNotification(message, type = 'info') { notification.textContent = ''; let iconClass = 'fa-info-circle'; if (type === 'success') iconClass = 'fa-check-circle'; else if (type === 'error') iconClass = 'fa-exclamation-circle'; else if (type === 'warning') iconClass = 'fa-exclamation-triangle'; notification.className = `notification ${type}`; notification.innerHTML = `<i class="fas ${iconClass}"></i> ${message}`; notification.classList.add('show'); setTimeout(() => { notification.classList.remove('show'); }, 4000); }
    function isImageFile(file) { const acceptedImageTypes = ['image/png', 'image/jpeg', 'image/bmp']; return file && acceptedImageTypes.includes(file.type); }
    function formatBytes(bytes, decimals = 2) { if (!+bytes) return '0 Bytes'; const k = 1024; const dm = decimals < 0 ? 0 : decimals; const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`; }
    function toggleInputVisibility(element, toggleButton) { const icon = toggleButton.querySelector('i'); if (element.type === 'password') { element.type = 'text'; icon.classList.replace('fa-eye', 'fa-eye-slash'); } else { element.type = 'password'; icon.classList.replace('fa-eye-slash', 'fa-eye'); } }
    function copyToClipboard(text, successMessage) { if (!text) { showNotification('Nothing to copy', 'warning'); return; } navigator.clipboard.writeText(text).then(() => { showNotification(successMessage, 'success'); addLog(`${successMessage} copied.`, 'info'); }).catch(err => { showNotification('Failed to copy: ' + err, 'error'); addLog(`Failed to copy ${successMessage}: ${err}`, 'error'); }); }
    function setupVisibilityToggle(button, element) { button.addEventListener('click', () => toggleInputVisibility(element, button)); }
    function setupCopyButton(button, element) { button.addEventListener('click', () => copyToClipboard(element.value, `${element.labels[0]?.textContent?.replace(':', '') || 'Text'} copied`)); }
  
    // === Theme Management ===
    function toggleTheme() { const isLight = document.body.classList.toggle('light-mode'); updateThemeButton(isLight); localStorage.setItem('theme', isLight ? 'light' : 'dark'); addLog(`Theme changed to ${isLight ? 'Light' : 'Dark'} Mode`, 'info'); }
    function updateThemeButton(isLight) { const icon = themeToggle.querySelector('i'); const text = themeToggle.querySelector('span'); if (isLight) { icon.className = 'fas fa-sun'; text.textContent = 'Light Mode'; } else { icon.className = 'fas fa-moon'; text.textContent = 'Dark Mode'; } }
  
    // === Tab Management ===
    function activateTab(selectedButton, tabId) {
    // Deactivate previous
    tabButtons.forEach(button => button.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));

    // Activate new
    selectedButton.classList.add('active');
    document.getElementById(tabId).classList.add('active');
    currentActiveTabId = tabId;
    addLog(`Switched to tab: ${selectedButton.textContent.trim()}`, 'info');

    // --- Control Graph Card Visibility ---
    if (tabId === 'batchTabContent' && lastBatchHideResults.length > 0 && graphSliderContainer.querySelector('.graph-slider-wrapper')) {
            batchGraphsCard.style.display = 'block';
            addLog('Displaying Batch Performance graph card.', 'info');
    } else {
            batchGraphsCard.style.display = 'none';
            if(tabId !== 'batchTabContent') addLog('Hiding Batch Performance graph card (switched tab).', 'info');
    }
}
  
    // === File Handling ===
    function setupDragDrop(area, callback) { ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => { area.addEventListener(eventName, preventDefaults, false); document.body.addEventListener(eventName, preventDefaults, false); }); ['dragenter', 'dragover'].forEach(eventName => area.addEventListener(eventName, () => area.classList.add('active'), false)); ['dragleave', 'drop'].forEach(eventName => area.addEventListener(eventName, () => area.classList.remove('active'), false)); area.addEventListener('drop', (e) => { const files = e.dataTransfer.files; if (files.length) { callback(files); } }, false); }
    function handleCoverImage(file) { if (!file) return; if (!isImageFile(file)) { showNotification('Invalid cover image type. Use PNG, JPG, or BMP.', 'error'); return; } originalCoverFilename = file.name.split('.').slice(0, -1).join('.') || 'image'; coverFilenameSpan.textContent = `${file.name} (${formatBytes(file.size)})`; coverFileDisplay.style.display = 'flex'; const reader = new FileReader(); reader.onload = function(e) { coverPreview.src = e.target.result; coverImageData = e.target.result; addLog(`Cover image loaded: ${file.name}`, 'success'); resetMetrics(); }; reader.onerror = () => { showNotification('Error reading cover image file.', 'error'); addLog(`Error reading cover image: ${file.name}`, 'error'); }; reader.readAsDataURL(file); }
    function handleStegoImage(file) { if (!file) return; if (!isImageFile(file)) { showNotification('Invalid stego image type. Use PNG, JPG, or BMP.', 'error'); return; } stegoFilenameSpan.textContent = `${file.name} (${formatBytes(file.size)})`; stegoFileDisplay.style.display = 'flex'; const reader = new FileReader(); reader.onload = function(e) { outputPreview.src = e.target.result; stegoImageData = e.target.result; addLog(`Stego image loaded: ${file.name}`, 'success'); extractedText.value = ''; encryptedExtracted.value = ''; extractedKey.value = ''; rawEncryptedKey.value = ''; }; reader.onerror = () => { showNotification('Error reading stego image file.', 'error'); addLog(`Error reading stego image: ${file.name}`, 'error'); }; reader.readAsDataURL(file); }
    function handleBatchCoverFiles(files) { handleBatchFiles(files, 'cover'); }
    function handleBatchStegoFiles(files) { handleBatchFiles(files, 'stego'); }
    function handleBatchFiles(files, type) { const fileListEl = type === 'cover' ? batchCoverFileList : batchStegoFileList; const fileArray = type === 'cover' ? batchCoverFiles : batchStegoFiles; const countSpan = type === 'cover' ? batchCoverFileCount : batchStegoFileCount; const maxFiles = 50; for (const file of files) { if (fileArray.length >= maxFiles) { showNotification(`Maximum batch size (${maxFiles}) reached.`, 'warning'); break; } if (isImageFile(file) && !fileArray.some(f => f.name === file.name && f.size === file.size)) { fileArray.push(file); } else if (!isImageFile(file)) { showNotification(`Skipping invalid file type: ${file.name}`, 'warning'); } } renderBatchFileList(type); }
    function renderBatchFileList(type) { const fileListEl = type === 'cover' ? batchCoverFileList : batchStegoFileList; const fileArray = type === 'cover' ? batchCoverFiles : batchStegoFiles; const countSpan = type === 'cover' ? batchCoverFileCount : batchStegoFileCount; fileListEl.innerHTML = ''; countSpan.textContent = fileArray.length; fileArray.forEach((file, index) => { const li = document.createElement('li'); const nameSpan = document.createElement('span'); nameSpan.textContent = `${file.name} (${formatBytes(file.size)})`; const removeBtn = document.createElement('button'); removeBtn.className = 'remove-file'; removeBtn.innerHTML = '&times;'; removeBtn.title = 'Remove file'; removeBtn.onclick = (e) => { e.stopPropagation(); removeBatchFile(index, type); }; li.appendChild(nameSpan); li.appendChild(removeBtn); fileListEl.appendChild(li); }); }
    function removeBatchFile(index, type) { if (type === 'cover') batchCoverFiles.splice(index, 1); else batchStegoFiles.splice(index, 1); renderBatchFileList(type); }
    function clearBatchFiles(type) { if (type === 'cover') batchCoverFiles = []; else batchStegoFiles = []; renderBatchFileList(type); }
  
    // === Directory Browser ===
    function fetchSystemDirectories() { fetch('/api/get_system_directories').then(r => r.json()).then(d => { if(d.success) systemDirectories=d.directories; else addLog('Could not load system directories: ' + d.error, 'error'); }).catch(e => addLog('Network error loading system directories: ' + e, 'error')); }
    function browseOutputDirectory(purpose) { modalTitle.textContent = 'Select Output Directory'; activeModalPurpose = purpose; const startPath = (purpose === 'batchOutput' ? batchOutputPath.value : outputPath.value) || DEFAULT_PATHS.outputDir; fetchDirectories(startPath); directoryModal.classList.add('show'); }
    function closeDirectoryModal() { directoryModal.classList.remove('show'); activeModalPurpose = null; }
    function fetchDirectories(path) { addLog(`Browsing directory: ${path}`, 'info'); currentPathSpan.textContent = 'Loading...'; directoryList.innerHTML = '<li>Loading...</li>'; fetch('/api/browse_directory', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: path }) }).then(r => r.json()).then(d => { if(d.success) populateDirectoryList(d); else { addLog(`Error browsing directory "${path}": ${d.error}`, 'error'); showNotification(`Error browsing: ${d.error}`, 'error'); currentPathSpan.textContent = `Error: ${d.error}`; directoryList.innerHTML = '<li>Could not load contents.</li>'; } }).catch(e => { addLog(`Network error browsing directory "${path}": ${e}`, 'error'); showNotification('Network error during browse', 'error'); currentPathSpan.textContent = 'Network Error'; directoryList.innerHTML = '<li>Network error.</li>'; }); }
    function populateDirectoryList(data) { directoryList.innerHTML = ''; currentPathSpan.textContent = data.path; if (data.parent && data.path !== data.parent) { const parentItem = createDirectoryItem('.. Parent Directory', data.parent, 'fa-level-up-alt'); directoryList.appendChild(parentItem); } if (data.directories && data.directories.length > 0) { data.directories.forEach(dir => { const dirItem = createDirectoryItem(dir.name, dir.path, 'fa-folder'); directoryList.appendChild(dirItem); }); } else if (!data.parent || data.path === data.parent) { const emptyItem = document.createElement('li'); emptyItem.innerHTML = '<i class="fas fa-info-circle" style="color: var(--medium-text);"></i> No sub-directories found.'; emptyItem.style.padding = '0.7rem 1rem'; emptyItem.style.color = 'var(--medium-text)'; directoryList.appendChild(emptyItem); } }
    function createDirectoryItem(name, path, iconClass) { const item = document.createElement('li'); item.className = 'directory-item'; item.innerHTML = `<i class="fas ${iconClass}"></i> ${name}`; item.addEventListener('click', () => fetchDirectories(path)); return item; }
    function selectCurrentDirectory() { const selectedPath = currentPathSpan.textContent; if (activeModalPurpose === 'output') outputPath.value = selectedPath; else if (activeModalPurpose === 'batchOutput') batchOutputPath.value = selectedPath; currentOutputDirectory = selectedPath; addLog(`Output directory (${activeModalPurpose}) set to: ${selectedPath}`, 'success'); showNotification('Output directory selected', 'success'); closeDirectoryModal(); }
  
    // === Key Management ===
    function generateKey() { addLog('Generating new key...', 'info'); fetch('/api/generate_key', { method: 'POST' }).then(r=>r.json()).then(d => { if(d.key) { currentKeyValue=d.key; displayKey(currentKeyValue); updateKeyStatus(true, 'New key generated.'); addLog('New AES-256 key generated.', 'success'); showNotification('New key generated', 'success'); } else handleKeyError('Error generating key', d.error); }).catch(e=>handleKeyError('Network error generating key', e)); }
    function loadKey() { const input = document.createElement('input'); input.type='file'; input.accept='.key,.txt'; input.onchange = function() { if(this.files.length) { const file = this.files[0]; addLog(`Loading key from: ${file.name}`, 'info'); const reader = new FileReader(); reader.onload = function(e) { try { const hexKey = convertBinaryKeyToHex(e.target.result); if(isValidHexKey(hexKey)) { currentKeyValue = hexKey; displayKey(currentKeyValue); updateKeyStatus(true, `Key loaded from ${file.name}.`); addLog(`Key loaded from ${file.name}.`, 'success'); showNotification('Key loaded', 'success'); } else { handleKeyError(`Invalid key format in ${file.name}`, 'Invalid 64-char hex key.'); } } catch(error) { handleKeyError(`Error reading key file ${file.name}`, error); } }; reader.onerror = (e) => handleKeyError(`Could not read key file ${file.name}`, e); reader.readAsText(file); } }; input.click(); }
    function convertBinaryKeyToHex(keyContent) { const cleaned = keyContent.toString().trim().replace(/[\s\r\n:-]/g, ''); if(/^[0-9a-fA-F]{64}$/.test(cleaned)) return cleaned.toLowerCase(); return ''; }
    function isValidHexKey(key) { return typeof key === 'string' && /^[0-9a-f]{64}$/i.test(key); }
    function displayKey(key) { keyDisplayContainer.style.display = 'block'; currentKey.value = key; currentKey.type = 'password'; const icon = toggleKeyVisibility.querySelector('i'); icon.classList.remove('fa-eye-slash'); icon.classList.add('fa-eye'); }
    function updateKeyStatus(hasKey, message = '') { if(hasKey) { keyStatus.innerHTML = `<i class="fas fa-check-circle" style="color: var(--success);"></i> <span>${message || 'Key is ready.'}</span>`; keyStatus.style.color = 'var(--success)'; } else { keyStatus.innerHTML = `<i class="fas fa-times-circle" style="color: var(--error);"></i> <span>${message || 'No valid key.'}</span>`; keyStatus.style.color = 'var(--error)'; } keyStatus.style.display = 'block'; }
    function handleKeyError(logMessage, errorDetails) { const details = errorDetails instanceof Error ? errorDetails.message : String(errorDetails); addLog(`${logMessage}: ${details}`, 'error'); showNotification(logMessage, 'error'); updateKeyStatus(false, logMessage); currentKeyValue = null; }
  
    // === Steganography Actions (Single Mode) ===
    function hideMessageAction() { if (!coverImageData) return showNotification('Select cover image.', 'warning'); if (!messageInput.value.trim()) return showNotification('Enter message.', 'warning'); if (!outputPath.value) return showNotification('Select output directory.', 'warning'); if (!currentKeyValue) return showNotification('Generate/Load key.', 'warning'); hideMessage(); }
    function extractMessageAction() { if (!stegoImageData) return showNotification('Select stego image.', 'warning'); extractMessage(); }
    function hideMessage() { addLog('Hiding message...', 'info'); showProgress(hideProgress, hideProgressBar, hideProgressText, 10); resetMetrics(); const timestamp = new Date().toISOString().replace(/[-:.]/g, '').replace('T', '_').slice(0, 15); const baseFilename = originalCoverFilename || 'stego'; const outputFilename = `${baseFilename}_${timestamp}.png`; const fullOutputPath = `${outputPath.value.replace(/\\/g, '/')}/${outputFilename}`; const keyFilename = `${baseFilename}_${timestamp}.key`; const keyPath = `${DEFAULT_PATHS.keysDir.replace(/\\/g, '/')}/${keyFilename}`; fetch('/api/hide_message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ coverImage: coverImageData, message: messageInput.value, key: currentKeyValue, useAES: document.getElementById('useAES').checked, enhancedBit: document.getElementById('enhancedBit').checked, adaptiveChannel: document.getElementById('adaptiveChannel').checked, errorCorrection: document.getElementById('errorCorrection').checked, embedKey: document.getElementById('embedKey').checked, outputPath: fullOutputPath, outputDirectory: outputPath.value, keyPath: keyPath }) }).then(r => r.json()).then(d => { if(d.success) { simulateProgress(hideProgressBar, hideProgressText, () => { hideProgress.style.display = 'none'; outputPreview.src = d.outputImage; encryptedMessage.value = d.encryptedData || ''; encryptedKey.value = d.encryptedKey || ''; updateMetrics(d.metrics || {}); addLog(`Message hidden. Saved to: ${d.savedPath}`, 'success'); showNotification('Message hidden!', 'success'); if (d.keySaved && d.keyPath) addLog(`Key reference saved: ${d.keyPath}`, 'info'); }); } else handleOperationError('Hiding failed', d.error, hideProgress); }).catch(e => handleOperationError('Network error hiding', e, hideProgress)); }
    function extractMessage() { addLog('Extracting message...', 'info'); showProgress(extractProgress, extractProgressBar, extractProgressText, 10); extractedText.value = ''; encryptedExtracted.value = ''; extractedKey.value = ''; rawEncryptedKey.value = ''; fetch('/api/extract_message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stegoImage: stegoImageData, key: currentKeyValue, useAES: document.getElementById('useAES').checked, enhancedBit: document.getElementById('enhancedBit').checked, adaptiveChannel: document.getElementById('adaptiveChannel').checked, extractKey: document.getElementById('embedKey').checked, returnRawData: true }) }).then(r => r.json()).then(d => { if(d.success) { simulateProgress(extractProgressBar, extractProgressText, () => { extractProgress.style.display = 'none'; extractedText.value = d.message || 'No message found.'; encryptedExtracted.value = d.rawData || ''; extractedKey.value = d.extractedKey || ''; rawEncryptedKey.value = d.rawKeyData || ''; if (d.extractedKey && !currentKeyValue) { currentKeyValue = d.extractedKey; displayKey(currentKeyValue); updateKeyStatus(true, 'Key extracted.'); addLog('Key extracted.', 'success'); } else if (d.extractedKey) addLog(`Key extracted: ${d.extractedKey.substring(0,8)}...`, 'info'); else if (document.getElementById('embedKey').checked) addLog('Attempted key extraction, none found.', 'warning'); addLog('Extraction complete.', 'success'); showNotification('Message extracted!', 'success'); }); } else { const errorMsg = d.error || (d.message && d.message.startsWith("ERROR:")) ? d.message : 'Unknown extraction error.'; handleOperationError('Extraction failed', errorMsg, extractProgress); encryptedExtracted.value = d.rawData || ''; extractedKey.value = d.extractedKey || ''; rawEncryptedKey.value = d.rawKeyData || ''; } }).catch(e => handleOperationError('Network error extraction', e, extractProgress)); }
    function handleOperationError(logPrefix, errorDetails, progressElement) { const details = errorDetails instanceof Error ? errorDetails.message : String(errorDetails); addLog(`${logPrefix}: ${details}`, 'error'); showNotification(logPrefix, 'error'); if (progressElement) progressElement.style.display = 'none'; }
  
    // === Batch Processing Actions ===
    function startBatchHideAction() {
        if (batchCoverFiles.length === 0) return showNotification('Select cover images for batch hide.', 'warning');
        if (!batchMessageInput.value.trim()) return showNotification('Enter message for batch hide.', 'warning');
        if (!batchOutputPath.value) return showNotification('Select output directory for batch hide.', 'warning');
        if (!currentKeyValue) return showNotification('Generate/Load key.', 'warning');
  
        // Reset graph display before starting
        graphSliderContainer.innerHTML = `
        <div class="initial-loading-graphs">
            <i class="fas fa-spinner fa-spin"></i> Waiting for batch process...
        </div>`;
      lastBatchHideResults = []; // Clear previous graph data trigger
      // Explicitly hide here in case it was visible from a previous run on another tab
      batchGraphsCard.style.display = 'none';

      startBatchHide();
    }

    function startBatchExtractAction() {
        if (batchStegoFiles.length === 0) return showNotification('Select stego images for batch extract.', 'warning');

        // Reset graph slider content and hide card
        graphSliderContainer.innerHTML = `
          <div class="initial-loading-graphs">
              <i class="fas fa-spinner fa-spin"></i> Waiting for batch process...
          </div>`;
        batchGraphsCard.style.display = 'none';
        lastBatchHideResults = []; // Clear previous graph data trigger

        startBatchExtract();
    }


    function startBatchHide() {
        addLog(`Starting Batch Hide for ${batchCoverFiles.length} images...`, 'info');
        startBatchHideBtn.disabled = true; startBatchHideBtn.innerHTML = '<i class="fas fa-spinner loading"></i> Processing...';
        batchHideResultsContainer.style.display = 'none'; batchHideResultsBody.innerHTML = '';
        showProgress(batchHideProgress, batchHideProgressBar, batchHideProgressText, 0);

        const formData = new FormData();
        formData.append('message', batchMessageInput.value);
        formData.append('key', currentKeyValue);
        formData.append('outputDirectory', batchOutputPath.value);
        formData.append('useAES', document.getElementById('useAES').checked);
        formData.append('enhancedBit', document.getElementById('enhancedBit').checked);
        formData.append('adaptiveChannel', document.getElementById('adaptiveChannel').checked);
        formData.append('errorCorrection', document.getElementById('errorCorrection').checked);
        formData.append('embedKey', document.getElementById('embedKey').checked);
        batchCoverFiles.forEach(file => formData.append('coverImages', file, file.name));

        fetch('/api/batch_hide', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(d => handleBatchHideComplete(d)) // Modified handler
        .catch(e => handleOperationError('Network error during Batch Hide', e, batchHideProgress))
        .finally(() => {
            startBatchHideBtn.disabled = false; startBatchHideBtn.innerHTML = '<i class="fas fa-cogs"></i> Start Batch Hide';
            batchHideProgressBar.style.width = '100%'; batchHideProgressText.textContent = 'Complete';
            setTimeout(() => { batchHideProgress.style.display = 'none'; }, 1500);
        });
    }
    function startBatchExtract() {
        addLog(`Starting Batch Extract for ${batchStegoFiles.length} images...`, 'info');
        startBatchExtractBtn.disabled = true; startBatchExtractBtn.innerHTML = '<i class="fas fa-spinner loading"></i> Processing...';
        batchExtractResultsContainer.style.display = 'none'; batchExtractResultsBody.innerHTML = '';
        showProgress(batchExtractProgress, batchExtractProgressBar, batchExtractProgressText, 0);

        const formData = new FormData();
        formData.append('key', currentKeyValue || '');
        formData.append('useAES', document.getElementById('useAES').checked);
        formData.append('enhancedBit', document.getElementById('enhancedBit').checked);
        formData.append('adaptiveChannel', document.getElementById('adaptiveChannel').checked);
        formData.append('extractKey', document.getElementById('embedKey').checked);
        formData.append('returnRawData', true);
        batchStegoFiles.forEach(file => formData.append('stegoImages', file, file.name));

        fetch('/api/batch_extract', { method: 'POST', body: formData })
        .then(r => r.json())
        .then(d => handleBatchExtractComplete(d)) // Modified handler
        .catch(e => handleOperationError('Network error during Batch Extract', e, batchExtractProgress))
        .finally(() => {
            startBatchExtractBtn.disabled = false; startBatchExtractBtn.innerHTML = '<i class="fas fa-cogs"></i> Start Batch Extract';
            batchExtractProgressBar.style.width = '100%'; batchExtractProgressText.textContent = 'Complete';
            setTimeout(() => { batchExtractProgress.style.display = 'none'; }, 1500);
        });
    }
  
    // === Batch Results Display ===
    function displayBatchHideResults(results, overallError = null) {
        batchHideResultsBody.innerHTML = '';
        batchHideResultsContainer.style.display = 'none';
        lastBatchHideResults = []; // Clear results for graph check initially

        if (overallError) {
             const row = batchHideResultsBody.insertRow(); const cell = row.insertCell(); cell.colSpan = 11; cell.innerHTML = `<span class="status-error">Overall Error: ${overallError}</span>`; addLog(`Batch Hide Failed (Overall): ${overallError}`, 'error');
        }

        let successCount = 0;
        let totalPsnr = 0, totalSsim = 0, totalCapacity = 0, totalBer = 0;

        if (results && results.length > 0) {
            results.forEach(result => {
                const row = batchHideResultsBody.insertRow();
                row.insertCell().textContent = result.filename || 'N/A';
                const statusCell = row.insertCell(); statusCell.textContent = result.success ? 'Success' : 'Error'; statusCell.className = result.success ? 'status-success' : 'status-error';
                const pathCell = row.insertCell(); pathCell.textContent = result.outputPath || (result.error ? result.error : 'N/A'); if (result.error) pathCell.classList.add('status-error'); pathCell.style.wordBreak = 'break-all';
                const psnrVal = result.success ? (result.metrics?.psnr ?? result.psnr ?? null) : null; const ssimVal = result.success ? (result.metrics?.ssim ?? result.ssim ?? null) : null; const capVal = result.success ? (result.metrics?.capacity ?? result.capacity ?? null) : null; const berVal = result.success ? (result.metrics?.ber ?? result.ber ?? null) : null;
                row.insertCell().textContent = psnrVal !== null ? psnrVal.toFixed(2) : '--'; row.insertCell().textContent = ssimVal !== null ? ssimVal.toFixed(4) : '--'; row.insertCell().textContent = capVal !== null ? capVal.toFixed(4) : '--'; row.insertCell().textContent = berVal !== null ? (berVal < 0.0001 && berVal !== 0 ? berVal.toExponential(2) : berVal.toFixed(4)) : '--';
                const msgCell = row.insertCell(); const msgSpan = document.createElement('span'); msgSpan.className = 'message-preview'; msgSpan.textContent = result.message ? String(result.message) : '--'; msgSpan.title = result.message ? String(result.message) : '--'; msgCell.appendChild(msgSpan);
                const keyCell = row.insertCell(); const keySpan = document.createElement('span'); keySpan.className = 'message-preview'; keySpan.textContent = result.key ? `${String(result.key).substring(0, 8)}...` : '--'; keySpan.title = result.key ? String(result.key) : '--'; keyCell.appendChild(keySpan);
                const encMsgCell = row.insertCell(); const encMsgSpan = document.createElement('span'); encMsgSpan.className = 'message-preview'; encMsgSpan.textContent = result.encryptedData ? `${String(result.encryptedData).substring(0, 20)}...` : '--'; encMsgSpan.title = result.encryptedData ? String(result.encryptedData) : '--'; encMsgCell.appendChild(encMsgSpan);
                const encKeyCell = row.insertCell(); const encKeySpan = document.createElement('span'); encKeySpan.className = 'message-preview'; encKeySpan.textContent = result.encryptedKey ? `${String(result.encryptedKey).substring(0, 20)}...` : '--'; encKeySpan.title = result.encryptedKey ? String(result.encryptedKey) : '--'; encKeyCell.appendChild(encKeySpan);

                if (result.success) {
                    successCount++;
                    lastBatchHideResults.push(result); // Add successful result for graphing
                    let logMsg = `Batch Hide Success: '${result.filename}' -> '${result.outputPath}'`; if (result.keySavePath) logMsg += ` (Key saved: '${result.keySavePath}')`; addLog(logMsg, 'success');
                    if (psnrVal !== null) totalPsnr += psnrVal; if (ssimVal !== null) totalSsim += ssimVal; if (capVal !== null) totalCapacity += capVal; if (berVal !== null) totalBer += berVal;
                } else addLog(`Batch Hide Error: '${result.filename}': ${result.error || 'Unknown error'}`, 'error');
            });
            batchHideResultsContainer.style.display = 'block';
        } else if (!overallError) {
             const row = batchHideResultsBody.insertRow(); const cell = row.insertCell(); cell.colSpan = 11; cell.textContent = 'No results to display.'; batchHideResultsContainer.style.display = 'block'; addLog('Batch Hide: No files processed or no results returned.', 'warning');
        }

        addLog(`Batch Hide results processing complete. ${successCount} successful, ${(results?.length || 0) - successCount} failed.`, 'info');
        if (successCount > 0) updateAverageMetrics({ psnr: totalPsnr / successCount, ssim: totalSsim / successCount, capacity: totalCapacity / successCount, ber: totalBer / successCount });
        else if (results && results.length > 0) resetMetrics();
        else if (!overallError) resetMetrics();
    }

    function displayBatchExtractResults(results, overallError = null) {
        batchExtractResultsBody.innerHTML = '';
        batchExtractResultsContainer.style.display = 'none';
        if (overallError) { const row = batchExtractResultsBody.insertRow(); const cell = row.insertCell(); cell.colSpan = 6; cell.innerHTML = `<span class="status-error">Overall Error: ${overallError}</span>`; addLog(`Batch Extract Failed (Overall): ${overallError}`, 'error'); }
        let successCount = 0;
        if (results && results.length > 0) {
            results.forEach(result => {
                const row = batchExtractResultsBody.insertRow();
                row.insertCell().textContent = result.filename || 'N/A';
                const statusCell = row.insertCell(); statusCell.textContent = result.success ? 'Success' : 'Error'; statusCell.className = result.success ? 'status-success' : 'status-error';
                const msgCell = row.insertCell(); const msgSpan = document.createElement('span'); msgSpan.className = 'message-preview'; msgSpan.textContent = result.success ? (result.message || 'N/A') : (result.error || 'N/A'); msgSpan.title = result.success ? (result.message || 'N/A') : (result.error || 'N/A'); msgCell.appendChild(msgSpan);
                const keyCell = row.insertCell(); const keySpan = document.createElement('span'); keySpan.className = 'message-preview'; keySpan.textContent = result.success && result.extractedKey ? `${String(result.extractedKey).substring(0, 8)}...` : '--'; keySpan.title = result.success && result.extractedKey ? String(result.extractedKey) : '--'; keyCell.appendChild(keySpan);
                const rawEncMsgCell = row.insertCell(); const rawEncMsgSpan = document.createElement('span'); rawEncMsgSpan.className = 'message-preview'; rawEncMsgSpan.textContent = result.encryptedData ? `${String(result.encryptedData).substring(0, 20)}...` : '--'; rawEncMsgSpan.title = result.encryptedData ? String(result.encryptedData) : '--'; rawEncMsgCell.appendChild(rawEncMsgSpan);
                const rawEncKeyCell = row.insertCell(); const rawEncKeySpan = document.createElement('span'); rawEncKeySpan.className = 'message-preview'; rawEncKeySpan.textContent = result.encryptedKey ? `${String(result.encryptedKey).substring(0, 20)}...` : '--'; rawEncKeySpan.title = result.encryptedKey ? String(result.encryptedKey) : '--'; rawEncKeyCell.appendChild(rawEncKeySpan);
                if (result.success) { successCount++; let logMsg = `Batch Extract Success: '${result.filename}' -> Msg: ${String(result.message || '').substring(0, 30)}...`; if(result.extractedKey) logMsg += ` (Key: ${String(result.extractedKey).substring(0,8)}...)`; addLog(logMsg, 'success'); }
                else addLog(`Batch Extract Error: '${result.filename}': ${result.error || result.message || 'Unknown error'}`, 'error');
            });
            batchExtractResultsContainer.style.display = 'block';
        } else if (!overallError) { const row = batchExtractResultsBody.insertRow(); const cell = row.insertCell(); cell.colSpan = 6; cell.textContent = 'No results to display.'; batchExtractResultsContainer.style.display = 'block'; addLog('Batch Extract: No files processed or no results returned.', 'warning'); }
        addLog(`Batch Extract results processing complete. ${successCount} successful, ${(results?.length || 0) - successCount} failed.`, 'info');
    }

  
    // === Progress & Metrics ===
    function showProgress(container, bar, text, initialPercent) { container.style.display = 'block'; bar.style.width = `${initialPercent}%`; text.textContent = `${initialPercent}%`; }
    function simulateProgress(bar, textElement, callback) { let currentProgress = parseInt(bar.style.width) || 10; const interval = setInterval(() => { currentProgress += Math.floor(Math.random() * 15) + 5; if (currentProgress >= 100) { currentProgress = 100; clearInterval(interval); bar.style.width = '100%'; textElement.textContent = '100%'; setTimeout(callback, 300); } else { bar.style.width = `${currentProgress}%`; textElement.textContent = `${currentProgress}%`; } }, 200); }
    function updateMetrics(metrics, isAverage = false) { const psnr = metrics?.psnr ?? 0; const ssim = metrics?.ssim ?? 0; const ber = metrics?.ber ?? 1; const capacity = metrics?.capacity ?? 0; const prefix = isAverage ? "Avg. " : ""; const sidebarMetricPara = document.querySelector('.sidebar .card:nth-child(2) p'); psnrValue.textContent = `${prefix}${psnr.toFixed(2)} dB`; ssimValue.textContent = `${prefix}${ssim.toFixed(4)}`; capacityValue.textContent = `${prefix}${capacity.toFixed(4)} bpp`; berValue.textContent = `${prefix}${ber < 0.0001 && ber !== 0 ? ber.toExponential(2) : ber.toFixed(4)}`; const psnrPercent = Math.min(Math.max(((psnr - 30) / 20) * 100, 0), 100); psnrBar.style.width = `${psnrPercent}%`; const ssimPercent = Math.min(Math.max(((ssim - 0.9) / 0.1) * 100, 0), 100); ssimBar.style.width = `${ssimPercent}%`; const capacityPercent = Math.min(Math.max((capacity / 2.0) * 100, 0), 100); capacityBar.style.width = `${capacityPercent}%`; const berPercent = Math.min(Math.max((1 - ber / 0.01) * 100, 0), 100); berBar.style.width = `${berPercent}%`; if (sidebarMetricPara) sidebarMetricPara.textContent = isAverage ? 'Metrics shown are averages for the last successful batch hide operation.' : 'Metrics shown are for the last single hide operation.'; const logType = isAverage ? 'Batch Average' : 'Single Mode'; addLog(`${logType} Metrics Updated - PSNR: ${psnr.toFixed(2)}, SSIM: ${ssim.toFixed(4)}, Capacity: ${capacity.toFixed(4)}, BER: ${ber.toExponential(2)}`, 'info'); }
    function updateAverageMetrics(avgMetrics) { updateMetrics(avgMetrics, true); }
    function resetMetrics() { psnrValue.textContent = '--'; ssimValue.textContent = '--'; berValue.textContent = '--'; capacityValue.textContent = '--'; psnrBar.style.width = '0%'; ssimBar.style.width = '0%'; berBar.style.width = '0%'; capacityBar.style.width = '0%'; const sidebarMetricPara = document.querySelector('.sidebar .card:nth-child(2) p'); if(sidebarMetricPara) sidebarMetricPara.textContent = 'Metrics are updated after a single hide operation.'; addLog('Metrics reset.', 'info'); }
  
     // === Graph Handling (Slider Implementation) ===
     function handleBatchHideComplete(data) {
        if (data.success) {
            displayBatchHideResults(data.results || []);
            if (lastBatchHideResults.length > 0) {
                triggerGraphGeneration(lastBatchHideResults);
            } else {
                 addLog('Batch Hide finished, but no files were processed successfully. Skipping graph generation.', 'warning');
                 if(currentActiveTabId === 'batchTabContent') {
                     batchGraphsCard.style.display = 'none';
                 }
            }
        } else {
            handleOperationError('Batch Hide failed', data.error || 'Unknown backend error', batchHideProgress);
            displayBatchHideResults(data.results || [], data.error);
            batchGraphsCard.style.display = 'none';
        }
    }
  
     function handleBatchExtractComplete(data) {
         if (data.success) {
             displayBatchExtractResults(data.results || []);
             addLog(`Batch Extract finished. Processed ${data.results?.length || 0} files.`, 'success');
             showNotification('Batch Extract completed!', 'success');
         } else {
             handleOperationError('Batch Extract failed', data.error || 'Unknown backend error', batchExtractProgress);
             displayBatchExtractResults(data.results || [], data.error);
         }
          batchGraphsCard.style.display = 'none'; // Always hide graphs after extraction for now
     }
  
     function triggerGraphGeneration(resultsData) {
        addLog('Requesting performance graph generation...', 'info');
        // Show the graph card only if the batch tab is currently active
        if (currentActiveTabId === 'batchTabContent') {
           batchGraphsCard.style.display = 'block';
        }
        graphSliderContainer.innerHTML = `
            <div class="initial-loading-graphs">
                <i class="fas fa-spinner fa-spin"></i> Generating performance graphs...
            </div>`; // Show loading inside the slider

        const graphPayload = resultsData.map(result => ({
            filename: result.filename,
            psnr: result.metrics?.psnr ?? result.psnr ?? 0,
            ssim: result.metrics?.ssim ?? result.ssim ?? 0,
            ber: result.metrics?.ber ?? result.ber ?? 1.0,
            capacity: result.metrics?.capacity ?? result.capacity ?? 0,
            file_size: result.file_size || 0
        }));

        fetch('/api/batch_performance_graphs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ results: graphPayload })
        })
        .then(response => {
             if (!response.ok) { throw new Error(`HTTP error! status: ${response.status}`); }
             return response.json();
        })
        .then(graphData => {
            if (graphData.success) {
                addLog('Graph data received successfully.', 'success');
                buildAndDisplayGraphSlider(graphData.graphs || []);
                // Ensure card is visible again if the user stayed on the batch tab
                if (currentActiveTabId === 'batchTabContent') {
                    batchGraphsCard.style.display = 'block';
                }
            } else {
                throw new Error(graphData.error || 'Unknown error generating graphs');
            }
        })
        .catch(error => {
            const errorMsg = `Failed to generate/display graphs: ${error.message}`;
            console.error(errorMsg, error); // Log full error to console
            addLog(errorMsg, 'error');
            showNotification('Error generating graphs.', 'error');
            graphSliderContainer.innerHTML = `
                <div class="graph-error" style="padding: 2rem;">
                    <i class="fas fa-exclamation-triangle"></i> Failed to generate graphs: ${error.message}. Check logs.
                </div>`;
            // Keep the card visible to show the error if on the batch tab
             if (currentActiveTabId === 'batchTabContent') {
                    batchGraphsCard.style.display = 'block';
             }
        });
    }
  
    function buildAndDisplayGraphSlider(graphUrls) {
        addLog(`Building slider for ${graphUrls.length} graphs.`, 'info');
        const container = graphSliderContainer;
        if (!container) { console.error("Graph slider container not found!"); return; }

        container.innerHTML = ''; // Clear previous content

        if (graphUrls.length === 0) {
            container.innerHTML = '<div class="graph-error" style="padding: 2rem;"><i class="fas fa-info-circle"></i> No graphs were generated for this batch.</div>';
            addLog('No graphs generated for the batch.', 'info');
            return;
        }

        // --- Create Slider Structure ---
        graphSliderWrapper = document.createElement('div');
        graphSliderWrapper.className = 'graph-slider-wrapper';

        const paginationContainer = document.createElement('div');
        paginationContainer.className = 'slider-pagination';

        graphSlides = [];
        graphPaginationDots = [];
        totalGraphSlides = 0;
        currentGraphIndex = 0;

         const graphTitleMap = {
           'scatter_plots.png': 'PSNR vs File Size & SSIM vs Capacity',
           'multi_metric_line.png': 'Multi-Metric Comparison',
           'radar_chart.png': 'Performance Radar Profile',
           'error_graph.png': 'Graph Generation Error'
         };


        // --- Populate Slides ---
        graphUrls.forEach((url) => {
            const filename = url.split('/').pop().split('?')[0];
            const isErrorGraph = filename === 'error_graph.png';
            const title = graphTitleMap[filename] || `Graph ${totalGraphSlides + 1}`;

            const slide = document.createElement('div');
            slide.className = 'graph-slider-slide';

            const heading = document.createElement('h4');
            heading.textContent = title;

            const imgWrapper = document.createElement('div');
            imgWrapper.className = 'graph-image-wrapper';

            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'graph-loading';
            loadingDiv.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Loading ${title}...`;

            imgWrapper.appendChild(loadingDiv);

            if (isErrorGraph) {
                const errorDiv = document.createElement('div');
                errorDiv.className = 'graph-error';
                errorDiv.innerHTML = `<i class="fas fa-exclamation-triangle"></i> Graph generation failed. Check logs.`;
                imgWrapper.appendChild(errorDiv);
                loadingDiv.style.display = 'none';
                addLog('Error graph detected in response.', 'error');
                 slide.appendChild(heading); // Still add heading and wrapper for consistency
                 slide.appendChild(imgWrapper);
                 // Append the error slide directly to the main container if needed? Or handle differently?
                 // For now, we'll just log it and not add it to the interactive slider parts.
                 // If you want it in the slider, you'd add it to graphSlides and graphSliderWrapper here
                 // but skip adding pagination dot and incrementing totalGraphSlides.
            } else {
                 const img = document.createElement('img');
                 img.className = 'performance-graph'; // Class for styling and targeting clicks
                 img.alt = title;
                 img.style.opacity = '0';
                 imgWrapper.appendChild(img);

                 // Preload image
                 const tempImg = new Image();
                 tempImg.onload = function() {
                     img.src = this.src; // Set src ONLY after load
                     img.style.opacity = '1';
                     img.classList.add('loaded'); // Add class for styling/click detection
                     loadingDiv.style.display = 'none';
                     addLog(`Graph loaded: ${title}`, 'info');
                 };
                 tempImg.onerror = function() {
                     console.error(`Failed to load graph image: ${url}`);
                     loadingDiv.innerHTML = `<i class="fas fa-exclamation-triangle"></i> Error loading ${title}`;
                     loadingDiv.style.color = 'var(--error)';
                     addLog(`Failed to load graph image: ${title}`, 'error');
                 };
                 tempImg.src = `${url}${url.includes('?') ? '&' : '?'}t=${Date.now()}`; // Cache buster

                 // Add heading and wrapper to the slide
                 slide.appendChild(heading);
                 slide.appendChild(imgWrapper);

                 // Create pagination dot only for valid graphs
                 const dot = document.createElement('span');
                 dot.className = 'slider-dot';
                 dot.dataset.index = totalGraphSlides;
                 paginationContainer.appendChild(dot);
                 graphPaginationDots.push(dot);

                 graphSlides.push(slide); // Add slide to array only if valid
                 graphSliderWrapper.appendChild(slide); // Append valid slide
                 totalGraphSlides++; // Increment count only for valid graphs
            }
        });

        // --- Add Navigation Buttons & Pagination ---
        container.appendChild(graphSliderWrapper); // Add the wrapper first

        if (totalGraphSlides > 1) {
            const prevButton = document.createElement('button');
            prevButton.className = 'slider-button prev';
            prevButton.innerHTML = '<i class="fas fa-chevron-left"></i>';
            prevButton.setAttribute('aria-label', 'Previous Graph');
            prevButton.disabled = true;

            const nextButton = document.createElement('button');
            nextButton.className = 'slider-button next';
            nextButton.innerHTML = '<i class="fas fa-chevron-right"></i>';
             nextButton.setAttribute('aria-label', 'Next Graph');

            container.appendChild(prevButton);
            container.appendChild(nextButton);
            container.appendChild(paginationContainer);
        }

        // --- Initialize Slider ---
        if(totalGraphSlides > 0) {
             updateGraphSlider(); // Set initial state
        } else {
            graphSliderWrapper.innerHTML = '<div class="graph-error" style="padding: 2rem;"><i class="fas fa-info-circle"></i> No valid graphs available.</div>';
        }
    }
  
      function updateGraphSlider() {
          if (!graphSliderWrapper || totalGraphSlides === 0) return;
  
          // Move the wrapper
          graphSliderWrapper.style.transform = `translateX(-${currentGraphIndex * 100}%)`;
  
          // Update pagination dots
          graphPaginationDots.forEach((dot, index) => {
              dot.classList.toggle('active', index === currentGraphIndex);
          });
  
          // Update navigation buttons state
          const prevButton = graphSliderContainer.querySelector('.slider-button.prev');
          const nextButton = graphSliderContainer.querySelector('.slider-button.next');
          if (prevButton) prevButton.disabled = currentGraphIndex === 0;
          if (nextButton) nextButton.disabled = currentGraphIndex >= totalGraphSlides - 1; // Use >= just in case
      }
  
      function nextGraphSlide() {
          if (currentGraphIndex < totalGraphSlides - 1) {
              currentGraphIndex++;
              updateGraphSlider();
          }
      }
  
      function prevGraphSlide() {
          if (currentGraphIndex > 0) {
              currentGraphIndex--;
              updateGraphSlider();
          }
      }
  
      function goToGraphSlide(index) {
          if (index >= 0 && index < totalGraphSlides) {
              currentGraphIndex = index;
              updateGraphSlider();
          }
      }
  
          // === NEW: Fullscreen Functions ===
    function openFullscreenGraph(src) {
        if (!src) return;
        addLog('Opening graph in fullscreen.', 'info');
        fullscreenGraphImage.src = src;
        fullscreenGraphModal.classList.add('show');
        // Add Escape key listener when modal is open
        document.addEventListener('keydown', handleEscapeKey);
    }

    function closeFullscreenGraph() {
        addLog('Closing fullscreen graph view.', 'info');
        fullscreenGraphModal.classList.remove('show');
        // Remove listener when modal is closed
        document.removeEventListener('keydown', handleEscapeKey);
        // Optional: Clear src after transition
        setTimeout(() => {
           if (!fullscreenGraphModal.classList.contains('show')) { // Check if still hidden
                fullscreenGraphImage.src = "";
           }
        }, 300); // Match CSS transition duration
    }

    function handleEscapeKey(event) {
        if (event.key === 'Escape') {
            closeFullscreenGraph();
        }
    }
    // === Start Application ===
    initApp();
  });