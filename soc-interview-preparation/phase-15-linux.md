[← Back to index](README.md) | Tier 3 — Know the concepts

# Phase 15 — Linux (Q358–369)

Lower weight than Windows for most SOC roles, but gaps here are noticeable. Know the log paths and the investigation commands.

## 358. Basic Linux commands you should know.

| Purpose | Commands |
|---|---|
| Navigation / files | `ls -la`, `cd`, `pwd`, `find / -name X`, `stat`, `file` |
| Reading files | `cat`, `less`, `head`, `tail -f`, `grep -i`, `awk`, `sed` |
| Processes | `ps aux`, `ps -ef --forest` (tree), `top`, `htop`, `pstree`, `lsof -p PID` |
| Network | `ss -tulpn` (modern), `netstat -tulpn`, `lsof -i`, `ip a`, `tcpdump` |
| Users / auth | `who`, `w`, `last`, `lastb`, `id`, `sudo -l`, `cat /etc/passwd`, `cat /etc/shadow` |
| Services | `systemctl status/list-units`, `service --status-all` |
| Scheduled tasks | `crontab -l`, `crontab -l -u user`, `ls /etc/cron*`, `systemctl list-timers` |
| Permissions | `chmod`, `chown`, `find / -perm -4000` (SUID binaries) |
| Packages | `rpm -qa`, `dpkg -l`, `yum/apt history` |
| Hashing | `sha256sum`, `md5sum` |

## 359. What is /var/log/auth.log?
On Debian/Ubuntu, the authentication log: SSH logins (successful and failed), `sudo` usage, `su`, user/group creation, PAM events, and session opens/closes. **On RHEL/CentOS/Fedora the equivalent is `/var/log/secure`** — know both, it's a common follow-up.

This is the Linux equivalent of the Windows Security log for authentication purposes, and the first file to read when investigating suspicious access.

## 360. What is /var/log/syslog?
The general system log on Debian/Ubuntu — kernel messages, service start/stop, cron execution, and general daemon activity. RHEL equivalent: `/var/log/messages`.

Other logs worth naming: `/var/log/wtmp` (login records, read with `last`), `/var/log/btmp` (failed logins, read with `lastb`), `/var/log/lastlog`, `/var/log/audit/audit.log` (auditd — the richest source when it's configured), and web server logs under `/var/log/apache2/` or `/var/log/nginx/`.

## 361. What is SSH?
Secure Shell — encrypted remote administration over TCP **22**. Authenticates by password or (preferably) public key. Also provides SCP/SFTP file transfer and port forwarding/tunneling — that last capability is security-relevant, because SSH tunnels can be used to bypass network controls and exfiltrate data through an allowed channel.

## 362. How do you investigate suspicious SSH login?
1. **Pull the auth log entries:**
```bash
grep "Accepted" /var/log/auth.log          # successful logins
grep "Failed password" /var/log/auth.log   # failures
last -f /var/log/wtmp                      # login history
lastb                                      # failed login history
```
2. **Establish who, from where, when, and how** — username, source IP, authentication method (password vs. publickey — a password login where keys are mandated is itself suspicious).
3. **Check for preceding brute force** — a burst of failures followed by a success from the same IP.
4. **Assess the source IP** — internal or external, expected geography, reputation.
5. **Check what the session did:**
```bash
grep "sudo" /var/log/auth.log              # privilege escalation attempts
cat ~/.bash_history                        # command history (may be cleared/disabled)
ps -ef --forest                            # processes still running
ss -tulpn                                  # listening ports / connections
```
6. **Check for persistence added** — new `~/.ssh/authorized_keys` entries (a classic and easily-missed backdoor), new users, new cron jobs, new systemd services.
7. **Check for account changes** — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` modification times.

## 363. How do you find running processes?
```bash
ps aux                        # all processes, detailed
ps -ef --forest               # process tree (parent-child, like Windows lineage)
pstree -p                     # visual tree with PIDs
top / htop                    # live view, resource usage
lsof -p <PID>                 # files and sockets a process has open
ls -l /proc/<PID>/exe         # true binary path — reveals deleted/masqueraded binaries
cat /proc/<PID>/cmdline       # full command line
```
`/proc/<PID>/exe` is the forensically important one: it shows the real executable even if the file was deleted after launch (shown as `(deleted)`), which is a common malware technique.

## 364. How do you find network connections?
```bash
ss -tulpn                     # listening + established, with process (modern)
netstat -tulpn                # older equivalent
ss -tp state established      # established connections with process
lsof -i                       # all network files by process
lsof -i :4444                 # what is using a specific port
```
Look for: unexpected listening ports (a backdoor), connections to unfamiliar external IPs, and processes making network connections that shouldn't.

## 365. How do you identify persistence mechanisms?
```bash
crontab -l; crontab -l -u <user>          # per-user cron
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly
cat /etc/crontab
systemctl list-units --type=service       # services
systemctl list-timers                     # systemd timers (modern cron equivalent)
ls -la /etc/systemd/system /lib/systemd/system
cat ~/.bashrc ~/.bash_profile /etc/profile /etc/rc.local   # shell/startup persistence
cat ~/.ssh/authorized_keys                # SSH key backdoor
find / -perm -4000 -type f 2>/dev/null    # SUID binaries (privilege escalation)
cat /etc/passwd | grep -v nologin         # accounts with shells
cat /etc/ld.so.preload                    # LD_PRELOAD rootkit persistence
```
Prioritize: cron/systemd timers, systemd services, SSH authorized_keys, shell profile files, and SUID binaries.

## 366. What is cron?
The Linux job scheduler — runs commands on a schedule, defined per-user (`crontab -e`) or system-wide (`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly}`). Format: minute, hour, day-of-month, month, day-of-week, then the command.

## 367. How can attackers abuse cron?
- **Persistence** — a cron job re-launching a backdoor every minute, so killing the process doesn't remove it.
- **Beaconing** — periodic outbound callbacks on a schedule.
- **Privilege escalation** — a writable script executed by root's crontab, or a cron job running a command with an unquoted/relative path an attacker can hijack.
- **Hiding** — planting entries in less-inspected locations (`/etc/cron.d/`, another user's crontab, or a systemd timer instead of cron) rather than the obvious root crontab.
- **Cleanup** — a scheduled job that periodically deletes logs or re-establishes the attacker's access after remediation.

Investigation: check **modification times** on all cron files and compare against your incident timeline — an unexplained recently-modified cron file is a strong finding.

## 368. How would you investigate a compromised Linux server?
1. **Preserve first** — if forensics is needed, capture memory and disk images before you change anything; isolate the host rather than powering it off.
2. **Authentication** — `/var/log/auth.log` or `/var/log/secure`, `last`, `lastb`: who logged in, from where, when, and any brute-force pattern.
3. **Processes** — `ps -ef --forest`, and check `/proc/<PID>/exe` for deleted or masqueraded binaries.
4. **Network** — `ss -tulpn` for unexpected listeners and outbound connections.
5. **Persistence** — cron, systemd services/timers, `authorized_keys`, shell profiles, `/etc/rc.local`, LD_PRELOAD ([Q365](#365-how-do-you-identify-persistence-mechanisms)).
6. **Accounts** — new users, UID 0 accounts other than root, `/etc/sudoers` changes, modified `/etc/passwd`/`/etc/shadow`.
7. **Files** — recently modified files (`find / -mtime -7 -type f`), files in `/tmp`, `/dev/shm`, `/var/tmp` (common staging directories), and SUID binaries.
8. **History** — `~/.bash_history` for every user (note it's often cleared or linked to `/dev/null` by attackers — its *absence* is itself evidence).
9. **Integrity** — compare installed packages against their expected checksums (`rpm -Va`, `debsums`) to find tampered binaries.
10. **Web logs** if it's a web server — look for web shell access patterns and exploitation attempts.
11. **Scope** — did the attacker move to other hosts, and are the credentials/SSH keys on this box used elsewhere?

## 369. What indicators would suggest privilege escalation on Linux?
- `sudo` usage in auth logs by accounts that shouldn't have it, or repeated `sudo` failures followed by a success.
- **New SUID/SGID binaries**, or SUID set on unusual files (`find / -perm -4000 -newer /etc/hostname`).
- Modifications to `/etc/sudoers` or `/etc/sudoers.d/`.
- New accounts, especially any with **UID 0** other than root.
- A user added to a privileged group (`wheel`, `sudo`, `admin`, `docker` — docker group membership is effectively root).
- Kernel exploit indicators — unusual kernel messages, unexpected module loads (`lsmod`), crashes.
- Processes running as root whose parent is a non-root user process.
- Modified cron jobs or systemd units running as root that a non-root user can write to.
- Container escapes on containerized hosts — privileged containers, mounted host filesystems, exposed Docker sockets.

---
[← Back to index](README.md) · [← Phase 14](phase-14-firewalls-network-security.md) · [Next: Phase 16 — Incident Response Scenarios →](phase-16-incident-response-scenarios.md)
