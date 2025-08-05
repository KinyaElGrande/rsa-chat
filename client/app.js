let ws = null;
let connected = false;
let publicKey = null;
let privateKey = null;
let keysGenerated = false;

async function generateKeysAsync() {
  const generateBtn = document.getElementById("generateKeysBtn");
  const generateBtnText = document.getElementById("generateBtnText");
  const generateSpinner = document.getElementById("generateSpinner");

  // Show loading state
  generateBtn.disabled = true;
  generateBtnText.textContent = "Generating Keys...";
  generateSpinner.classList.remove("hidden");

  try {
    const response = await fetch("http://localhost:8080/generate-keys", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    if (data.success) {
      publicKey = data.keys.PublicKey;
      privateKey = data.keys.PrivateKey;
      keysGenerated = true;

      // Display the keys in the UI
      displayKeys(publicKey, privateKey);

      document.getElementById("keyGenerationStep").classList.add("hidden");
      document.getElementById("keysDisplay").classList.remove("hidden");

      updateConnectButton();
    } else {
      throw new Error(data.error || "Failed to generate keys");
    }
  } catch (error) {
    console.error("Key generation error:", error);
    showError("Failed to generate keys: " + error.message);

    // Reset button state
    generateBtn.disabled = false;
    generateBtnText.textContent = "Generate RSA Keys";
    generateSpinner.classList.add("hidden");
  }
}

function displayKeys(pubKey, privKey) {
  document.getElementById("publicKeyDisplay").value = pubKey;
  document.getElementById("privateKeyDisplay").value = privKey;
}

function regenerateKeys() {
  document.getElementById("keyGenerationStep").classList.remove("hidden");
  document.getElementById("keysDisplay").classList.add("hidden");

  // Reset button state
  const generateBtn = document.getElementById("generateKeysBtn");
  const generateBtnText = document.getElementById("generateBtnText");
  const generateSpinner = document.getElementById("generateSpinner");

  generateBtn.disabled = false;
  generateBtnText.textContent = "Generate RSA Keys";
  generateSpinner.classList.add("hidden");

  // Clear stored keys
  publicKey = null;
  privateKey = null;
  keysGenerated = false;

  // Update connect button
  updateConnectButton();
}

function updateConnectButton() {
  const connectBtn = document.getElementById("connectBtn");
  const connectBtnText = document.getElementById("connectBtnText");

  if (keysGenerated) {
    connectBtn.disabled = false;
    connectBtnText.textContent = "Connect to Server";
    connectBtn.classList.remove("bg-gray-400");
    connectBtn.classList.add("bg-primary");
  } else {
    connectBtn.disabled = true;
    connectBtnText.textContent = "Generate Keys First";
    connectBtn.classList.remove("bg-primary");
    connectBtn.classList.add("bg-gray-400");
  }
}

function togglePrivateKeyVisibility() {
  const privateKeyField = document.getElementById("privateKeyDisplay");
  const eyeOpen = document.getElementById("eyeOpen");
  const eyeClosed = document.getElementById("eyeClosed");

  if (privateKeyField.type === "password") {
    privateKeyField.type = "text";
    eyeOpen.classList.add("hidden");
    eyeClosed.classList.remove("hidden");
  } else {
    privateKeyField.type = "password";
    eyeOpen.classList.remove("hidden");
    eyeClosed.classList.add("hidden");
  }
}

async function copyToClipboard(elementId, copiedIconId) {
  const element = document.getElementById(elementId);
  const copyIcon = document.getElementById(
    elementId.replace("Display", "CopyIcon"),
  );
  const copiedIcon = document.getElementById(copiedIconId);

  try {
    await navigator.clipboard.writeText(element.value);

    copyIcon.classList.add("hidden");
    copiedIcon.classList.remove("hidden");

    // Reset after 2 seconds
    setTimeout(() => {
      copyIcon.classList.remove("hidden");
      copiedIcon.classList.add("hidden");
    }, 2000);
  } catch (err) {
    console.error("Failed to copy: ", err);
    showError("Failed to copy to clipboard");
  }
}

function showError(message) {
  const errorDiv = document.getElementById("loginError");
  errorDiv.textContent = message;
  setTimeout(() => {
    errorDiv.textContent = "";
  }, 5000);
}

async function connect() {
  if (!keysGenerated) {
    showError("Please generate RSA keys first");
    return;
  }

  const serverUrl = document.getElementById("serverUrl").value;
  const authToken = document.getElementById("authToken").value;
  const errorDiv = document.getElementById("loginError");
  const connectBtn = document.getElementById("connectBtn");
  const connectBtnText = document.getElementById("connectBtnText");

  if (!serverUrl || !authToken) {
    errorDiv.textContent = "Please enter both server URL and token";
    return;
  }

  connectBtn.disabled = true;
  connectBtnText.textContent = "Connecting...";
  errorDiv.textContent = "";

  try {
    const wsUrl = `${serverUrl}?token=${encodeURIComponent(authToken)}`;
    ws = new WebSocket(wsUrl);

    ws.onopen = async function () {
      connected = true;
      updateStatus(true);

      document.getElementById("keySection").classList.add("hidden");
      document.getElementById("loginForm").classList.add("hidden");
      document.getElementById("chatContainer").classList.remove("hidden");

      addSystemMessage("Connected to server");

      // Send key exchange message
      const keyExchangeMsg = {
        type: "keys-exchange",
        publicKey: publicKey,
      };
      ws.send(JSON.stringify(keyExchangeMsg));
      addSystemMessage("Key exchange sent");
    };

    ws.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        handleMessage(data);
      } catch (error) {
        console.error("Error parsing message:", error);
      }
    };

    ws.onclose = function () {
      connected = false;
      updateStatus(false);
      addSystemMessage("Disconnected from server");
    };

    ws.onerror = function (error) {
      console.error("WebSocket error:", error);
      errorDiv.textContent = "Failed to connect to server";
      connectBtn.disabled = false;
      connectBtnText.textContent = "Connect to Server";
    };
  } catch (error) {
    console.error("Connection error:", error);
    errorDiv.textContent = "Connection failed: " + error.message;
    connectBtn.disabled = false;
    connectBtnText.textContent = "Connect to Server";
  }
}

function handleMessage(data) {
  switch (data.type) {
    case "keys-exchange":
      addSystemMessage(`${data.from} joined the chat`);
      break;

    case "message":
      const isOwnMessage = !data.from;
      addMessage(data.key, data.data, data.from || "You", isOwnMessage);
      break;

    default:
      console.log("Unknown message type:", data.type);
  }
}

async function sendMessage() {
  const input = document.getElementById("messageInput");
  const message = input.value.trim();

  if (!message || !connected) return;

  try {
    const messageData = {
      type: "message",
      data: message,
      publicKey: publicKey || "",
    };

    ws.send(JSON.stringify(messageData));
    input.value = "";
  } catch (error) {
    console.error("Error sending message:", error);
    addSystemMessage("Failed to send message");
  }
}

function handleKeyPress(event) {
  if (event.key === "Enter") {
    event.preventDefault();
    sendMessage();
  }
}

function addMessage(key, content, sender, isOwn = false) {
  const messagesDiv = document.getElementById("messages");
  const messageDiv = document.createElement("div");

  const timestamp = new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });

  if (!isOwn) {
    content = decryptMessage(key, content);
  }

  messageDiv.className = `p-3 rounded-lg max-w-xs ${isOwn ? "bg-primary text-white ml-auto" : "bg-white border shadow-sm"}`;
  messageDiv.innerHTML = `
        <div class="text-xs opacity-70 mb-1">${sender} • ${timestamp}</div>
        <div class="text-sm">${escapeHtml(content)}</div>
    `;

  messagesDiv.appendChild(messageDiv);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function addSystemMessage(content) {
  const messagesDiv = document.getElementById("messages");
  const messageDiv = document.createElement("div");
  messageDiv.className =
    "text-center text-xs text-gray-500 py-2 px-3 bg-gray-100 rounded-lg mx-auto max-w-fit";
  messageDiv.textContent = content;

  messagesDiv.appendChild(messageDiv);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function updateStatus(isConnected) {
  const status = document.getElementById("status");
  const statusText = document.getElementById("statusText");

  if (isConnected) {
    status.className = "w-3 h-3 bg-green-500 rounded-full";
    statusText.textContent = "Connected";
  } else {
    status.className = "w-3 h-3 bg-red-500 rounded-full";
    statusText.textContent = "Disconnected";
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function decryptMessage(encryptedAESKey, encryptedData) {
  try {
    const privateKeyPEM = forge.util.decode64(privateKey);
    const pkey = forge.pki.privateKeyFromPem(privateKeyPEM);
    const encryptedKeyBytes = forge.util.decode64(encryptedAESKey);
    const decryptedAESSecretKeyRaw = pkey.decrypt(
      encryptedKeyBytes,
      "RSAES-PKCS1-V1_5",
    );

    const decryptedAESSecretKey = forge.util.createBuffer(
      decryptedAESSecretKeyRaw,
    );

    const encryptedBytes = forge.util.decode64(encryptedData);

    if (encryptedBytes.length < 28) {
      throw new Error("Encrypted data too short");
    }

    const nonce = encryptedBytes.substring(0, 12);
    const ciphertextWithTag = encryptedBytes.substring(12);
    const tag = ciphertextWithTag.substring(ciphertextWithTag.length - 16);
    const ciphertext = ciphertextWithTag.substring(
      0,
      ciphertextWithTag.length - 16,
    );

    const decipher = forge.cipher.createDecipher(
      "AES-GCM",
      decryptedAESSecretKey,
    );

    decipher.start({
      iv: forge.util.createBuffer(nonce),
      tagLength: 128,
      tag: forge.util.createBuffer(tag),
    });

    decipher.update(forge.util.createBuffer(ciphertext));
    const verified = decipher.finish();

    if (!verified) {
      throw new Error(
        "Authentication verification failed - invalid tag or wrong key",
      );
    }

    return decipher.output.toString();
  } catch (error) {
    console.error("Decryption failed:", error.message);
    throw error;
  }
}

// Initialize the UI state
updateConnectButton();
