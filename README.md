(IN PROCESS: NOT WORKING)
# OpenP2P

**OpenP2P** is a lightweight, terminal-based application for secure, direct peer-to-peer (P2P) messaging and file transfer. Unlike many existing solutions, it prioritizes user privacy by eliminating account registration and leveraging direct connections between users.

## 🚀 Key Features

* **No Accounts**: Start chatting instantly without creating an account or providing an email address.
* **Direct P2P**: Uses TCP Hole Punching to establish direct connections between peers, bypassing NAT and minimizing reliance on third-party servers once connected.
* **End-to-End Encryption (E2EE)**: All communications are secured using libsodium’s industry-standard cryptographic primitives.
* **Integrated Messaging**: Supports real-time, encrypted chat alongside file transfers.
* **Secure File Transfer**: Features a robust protocol with file offers, manual acceptance, and resume-safe partial writes.
* **Real-time Progress**: View transfer speeds (MB/s), completion percentages, and estimated time of arrival (ETA) during file exchanges.

## 🛠 Architecture

OpenP2P consists of two primary components:

1.  **Rendezvous Server**: A lightweight discovery service that facilitates peer matching via Room IDs and passwords. It never touches your actual chat or file data.
2.  **Peer Client**: The core application that handles hole punching, performs the cryptographic handshake, and maintains the direct P2P data stream.

## 🛡 Security Model

* **Key Exchange**: X25519 (via `crypto_kx_*`) is used to derive unique session keys for every connection.
* **Encryption**: All data is encrypted and authenticated using XChaCha20-Poly1305-IETF.
* **Forward Compatibility**: The protocol includes internal type-tagging to distinguish between chat messages and file protocol metadata.

## 📦 Building and Installation

The project is written in C11 and requires `libsodium`.

```bash
# Clone the repository
git clone https://github.com/YerdosNar/OpenP2P.git
cd OpenP2P

# Compile both the peer and rendezvous server
make
```

## 📋 Usage

### 1. Start the Rendezvous Server
The server should be hosted on a machine with a public IP.
```bash
./rendezvous -p 8888 -l con.log
```

### 2. Connect as a Peer
Peers connect to the server to find one another. You can specify a Room ID once prompted.
```bash
./peer -d your-rendezvous-domain.com -s 8888
```

### 3. File Transfer Command
Within the chat interface, use the following command to initiate a transfer:
```text
/sendfile
```
You will be prompted to enter the path to the file you wish to send.

## ⚖️ How it Compares

| Feature | OpenP2P | ToffeeShare | Croc |
| :--- | :--- | :--- | :--- |
| **Account Required** | No | No | No |
| **Messaging** | Yes | No | No |
| **P2P Connection** | Direct (Hole Punch) | Browser-based | Relay (often) |
| **Interface** | Terminal | Web/Mobile | Terminal |
