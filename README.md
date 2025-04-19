# SOC Lab Project

## About the project
This project is to learn how to setup a very simple SOC environment. I use 2 servers, one server is acting as the SOC server where I host the ELK stack, and the other server is representing a client server. The client server is running an FTP server, SSH server for remote access and a Web server hosting a simple page. Aswell as a configured Suricata IDS/IPS software.
The aim of the project is to simulate an attack on the client server, using brute force techniques to try and access FTP and SSH, as well as reconnaisance attacks like port scanning.

## Brute Force Attacks
I used my Kali machine running on my other PC to perform a Brute Force attack on both the SSH and FTP ports running on my Ubuntu Client server.
### SSH Brute Force Attack Custom view in Kibana
![SSH Brute Force Attack] (pics/kibana_custom_view_brute-force_ssh.png)
