# SOC Lab Project

## About the project
This project is to learn how to setup a very simple SOC environment. I use 2 servers, one server is acting as the SOC server where I host the ELK stack, and the other server is representing a client server. The client server is running an FTP server, SSH server for remote access and a Web server hosting a simple page. Aswell as a configured Suricata IDS/IPS software.
The aim of the project is to simulate an attack on the client server, using brute force techniques to try and access FTP and SSH, as well as reconnaisance attacks like port scanning.

## Brute Force Attacks
I used my Kali machine running on my other PC to perform a Brute Force attack on both the SSH and FTP ports running on my Ubuntu Client server.
### SSH Brute Force Attack Custom view in Kibana
![kibana_custom_view_brute-force_ssh](https://github.com/user-attachments/assets/c3ebf2e8-dc8d-47da-9368-8fd5457a3cde)

I used an else if statement block to filter the system.auth dataset that contains the 'Failed password' string and using grok to match the message received for additional info, as well as add custom fields for easier viewing.
```
else if [event][dataset] == "system.auth" {
    # SSH logs
    if [message] =~ "Failed password" {
      mutate {
        add_tag => ["failed_ssh_login"]
      }
      grok {
        match =>  {"message" => "%{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:system} sshd\[%{NUMBER:process_id}\]: Failed password for %{DATA:user_status} %{USERNAME:username} from %{IP:source_ip} port %{NUMBER:source_port} ssh2" }
      }
      mutate {
        add_field => {
          "[event][type]" => "authentication_failure"
          "[event][category]" => "authentication"
          "[event][outcome]" => "failure"
        }
      }
    }
```
