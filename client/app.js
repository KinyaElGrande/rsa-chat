let ws = null;
let connected = false;
let publicKey = null;
let privateKey = null;

// read the file contents as text
function readFileContent(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

async function loadPublicKey() {
  const fileInput = document.getElementById("publicKeyFile");
  if (!fileInput.files[0]) {
    throw new Error("Please select a public key file");
  }
  return await readFileContent(fileInput.files[0]);
}

async function loadPrivateKey() {
  const fileInput = document.getElementById("privateKeyFile");
  if (!fileInput.files[0]) {
    throw new Error("Please select a private key file");
  }
  return await readFileContent(fileInput.files[0]);
}

async function connect() {
  const serverUrl = document.getElementById("serverUrl").value;
  const authToken = document.getElementById("authToken").value;
  const errorDiv = document.getElementById("loginError");
  const connectBtn = document.getElementById("connectBtn");

  if (!serverUrl || !authToken) {
    errorDiv.textContent = "Please enter both server URL and token";
    return;
  }

  connectBtn.disabled = true;
  connectBtn.textContent = "Connecting...";
  errorDiv.textContent = "";

  try {
    // Load keys from selected files
    publicKey = await loadPublicKey();
    privateKey = await loadPrivateKey();

    const wsUrl = `${serverUrl}?token=${encodeURIComponent(authToken)}`;
    ws = new WebSocket(wsUrl);

    ws.onopen = async function () {
      connected = true;
      updateStatus(true);

      document.getElementById("loginForm").classList.add("hidden");
      document.getElementById("chatContainer").classList.remove("hidden");

      addSystemMessage("Connected to server");

      // Send key exchange message with loaded public key
      // to save the public key on the server
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
      connectBtn.textContent = "Connect";
    };
  } catch (error) {
    console.error("Connection error:", error);
    errorDiv.textContent = "Connection failed: " + error.message;
    connectBtn.disabled = false;
    connectBtn.textContent = "Connect";
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

  messageDiv.className = `p-2 rounded max-w-xs ${isOwn ? "bg-primary text-white ml-auto" : "bg-white border"}`;
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
  messageDiv.className = "text-center text-xs text-gray-500 py-1";
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

// decrypt the message data using the private key, then decrypt the message using the secret key
function decryptMessage(encryptedAESKey, encryptedData) {
  try {
    // decrypt the aes key using the private key
    const pkey = forge.pki.privateKeyFromPem(privateKey);
    const encryptedKeyBytes = forge.util.decode64(encryptedAESKey);
    const decryptedAESSecretKeyRaw = pkey.decrypt(
      encryptedKeyBytes,
      "RSAES-PKCS1-V1_5",
    );

    // convert to proper format for forge
    const decryptedAESSecretKey = forge.util.createBuffer(
      decryptedAESSecretKeyRaw,
    );

    // Prepare the encrypted data
    const encryptedBytes = forge.util.decode64(encryptedData);

    if (encryptedBytes.length < 28) {
      throw new Error("Encrypted data too short");
    }

    // Extract encrypted components
    const nonce = encryptedBytes.substring(0, 12);
    const ciphertextWithTag = encryptedBytes.substring(12);

    // Extract the authentication tag (last 16 bytes)
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
