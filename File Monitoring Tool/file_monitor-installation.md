# Background File Monitor Installation Guide

This guide will help you set up the File Monitor script to run in the background as a system service.

## 1. Install the Script

1. Save the background monitor script to `/usr/local/bin/file_monitor.py`:

```bash
sudo nano /usr/local/bin/file_monitor.py
```

2. Copy and paste the provided Python script into the file.

3. Make the script executable:

```bash
sudo chmod +x /usr/local/bin/file_monitor.py
```

## 2. Create the Systemd Service

1. Create a service file:

```bash
sudo nano /etc/systemd/system/file-monitor.service
```

2. Copy and paste the provided service configuration into the file.

## 3. Configure the Monitor (Optional)

You can customize which directories to monitor by editing the service file:

```bash
sudo nano /etc/systemd/system/file-monitor.service
```

Change the ExecStart line to specify the directories you want to monitor:

```
ExecStart=/usr/local/bin/file_monitor.py --paths /home /var/www /etc /opt --verbose
```

By default, the script will monitor `/home`, `/var/www`, and `/etc` if no paths are specified.

## 4. Enable and Start the Service

1. Reload systemd to recognize the new service:

```bash
sudo systemctl daemon-reload
```

2. Enable the service to start at boot:

```bash
sudo systemctl enable file-monitor.service
```

3. Start the service:

```bash
sudo systemctl start file-monitor.service
```

4. Check the status to ensure it's running correctly:

```bash
sudo systemctl status file-monitor.service
```

## 5. View the Logs

### Service Logs

To view the service status and any error messages:

```bash
sudo journalctl -u file-monitor.service -f
```

### File Activity Logs

The file activity is logged to `/var/log/file_monitor.csv` by default. You can view it with:

```bash
sudo tail -f /var/log/file_monitor.csv
```

Or use a CSV viewer:

```bash
sudo apt-get install csvtool  # Install a CSV tool first
csvtool readable /var/log/file_monitor.csv | less
```

## 6. Stopping or Restarting the Service

To stop the service:

```bash
sudo systemctl stop file-monitor.service
```

To restart the service:

```bash
sudo systemctl restart file-monitor.service
```

## Troubleshooting

### Permission Issues

If you encounter permission issues, make sure:
- The script is running as root (as configured in the service file)
- The log directory has appropriate permissions
- You have `pyinotify` installed (`sudo apt-get install python3-pyinotify`)

### Performance Considerations

Monitoring many directories with deep hierarchies can consume system resources. If you experience performance issues:
- Limit monitoring to specific directories that are most important
- Exclude large or rapidly changing directories like `/tmp`
- Consider adding a filter to exclude certain file types

### Log Rotation

For long-term deployment, set up log rotation to prevent the log file from growing too large:

```bash
sudo nano /etc/logrotate.d/file-monitor
```

Add the following configuration:

```
/var/log/file_monitor.csv {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0644 root root
}
```
