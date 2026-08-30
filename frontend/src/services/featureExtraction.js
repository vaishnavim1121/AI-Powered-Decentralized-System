/**
 * Automatically extract features from a URL or file hash
 * Users just paste a URL or upload a file - no manual feature entry needed!
 */

// Extract features from a URL
export const extractFeaturesFromUrl = (url) => {
  try {
    const parsed = new URL(url);
    const urlString = url;
    
    // Feature 1: URL Length
    const length = urlString.length;
    
    // Feature 2: Number of digits in URL
    const digits = (urlString.match(/\d/g) || []).length;
    
    // Feature 3: Number of special characters
    const specialChars = (urlString.match(/[^a-zA-Z0-9]/g) || []).length;
    
    // Feature 4: Entropy (randomness of the URL)
    const charSet = new Set(urlString);
    const entropy = charSet.size / urlString.length * 10;
    
    // Feature 5: Has IP address instead of domain
    const hasIp = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlString) ? 1 : 0;
    
    return {
      features: [
        Math.min(length / 10, 10),        // Normalized length (0-10)
        Math.min(digits / 2, 10),          // Digit count (0-10)
        Math.min(specialChars / 3, 10),    // Special chars (0-10)
        Math.min(entropy * 2, 10),         // Entropy (0-10)
        hasIp * 10                         // Has IP (0 or 10)
      ],
      featureNames: ['URL Length', 'Digit Count', 'Special Chars', 'Entropy', 'Has IP']
    };
  } catch {
    // Invalid URL - return default low-risk features
    return {
      features: [3, 1, 1, 2, 0],
      featureNames: ['URL Length', 'Digit Count', 'Special Chars', 'Entropy', 'Has IP']
    };
  }
};

// Extract features from a file hash
export const extractFeaturesFromHash = (hash) => {
  const length = hash.length;
  const digits = (hash.match(/\d/g) || []).length;
  const letters = (hash.match(/[a-fA-F]/g) || []).length;
  const entropy = new Set(hash).size / length * 10;
  
  const suspicious = {
    features: [
      Math.min(length / 6, 10),     // Hash length (0-10)
      Math.min(digits / 3, 10),      // Digit count (0-10)
      Math.min(entropy, 10),         // Entropy (0-10)
      Math.min((letters / length) * 10, 10), // Hex ratio (0-10)
      length < 32 ? 8 : 2            // Short hash = suspicious
    ],
    featureNames: ['Hash Length', 'Digit Count', 'Entropy', 'Hex Ratio', 'Short Hash']
  };
  
  return suspicious;
};

// Calculate file entropy (for file uploads)
export const calculateFileEntropy = async (file) => {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const freq = {};
  for (const b of bytes) {
    freq[b] = (freq[b] || 0) + 1;
  }
  let entropy = 0;
  const len = bytes.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  // Normalize entropy to 0-10 scale (max entropy ~8 for bytes)
  return Math.min(entropy / 0.8, 10);
};

// Extract features from a file
export const extractFeaturesFromFile = async (file) => {
  const entropy = await calculateFileEntropy(file);
  const size = file.size;
  
  const features = [
    Math.min(size / 1000000, 10),     // File size in MB (0-10)
    Math.min(entropy, 10),            // Entropy (0-10)
    Math.min(file.name.length / 10, 10), // Filename length
    file.name.includes('.exe') || file.name.includes('.scr') ? 10 : 2,  // Executable
    file.name.match(/[^a-zA-Z0-9.]/g)?.length || 0 // Special chars in name
  ];
  
  return {
    features: features.map(f => Math.min(f, 10)),
    featureNames: ['File Size (MB)', 'Entropy', 'Name Length', 'Executable', 'Special Chars']
  };
};