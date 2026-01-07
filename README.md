# Satellite Security Simulator

A python based simulator that models a secure communication between a ground station and a satellite under an active network attack. The project is intended to demonstrate how modern cryptographic protocols work together alongside replay protection and incident detection to defends against real world communication threats. 

## Overview

This project simulates an uplink/downlink where an attacker has full control of the channel. The attacker can observe, replay, delay, drop, and tamper with packets. The attacker can't break the cryptography. This simulator shows the importance of protocol and design management, and that just relying on the strength of modern cryptography isn't enough. 

## Threat Model

The system is influenced on a Dolev - Yao style attack with the following capabilites: 
- Observe all packets on the link
- Replay previously valid packets
- Tamper with packets in transit
- Ability to inject malformed or altered packets
- Delay, drop, or reorder the traffic

However, the attack does not have:
- Ability to access cryptographic keys
- Break RSA/AES
- Compromise any of the ground station or the satellite software

## Security Design

1. Key Establishment
- The satellite has a long term RSA key pair
- The ground station generates a fresh symmetric session key
- The session key is encrypted with the satellites public key
- The key exchange only happens once at the start of the session

2. Secure Data Channel

All subsequent communication:
- AES-GCM Authenticated Encryption
- Packet headers are authenticated so metadata tampering would be detected

3. Replay Protection

To prevent replay attacks:
- Each packet carries a monotonic sequence number
- Recievers track the highest accepted sequence per direction
- Packets with an old or duplicate sequence would be rejected

4. Incident Detection

The simulator trakcs on reports:
- Authentication failures or reported tampered packets
- Replay detections
- Malformed packets

This shows how cryptographic failures becomes a signal of operational security. 

## Simulated Components

Ground Station
- Initiates the key exchange
- Sends the encrypted command packets
- Verifies encrypted telemetry responses

Satellite
- Accepts the key exchange
- Verifies then proccesses commands
- Sends encrypted telemetry responses

Communication Links
- Separate uplink and downlink
- Configured latency and packet loss

Attacker 
- Replay attack
- Packet tampering
- MITM style