# Raspberry Pi first handoff scope

The first Pulpo Node Raspberry Pi handoff is limited to device identification and synthetic tests.

Allowed:

- identify OS, Python version, hostname, and non-sensitive device characteristics;
- run the synthetic virtual-lamp proof in a disposable directory;
- import-check a GPIO adapter in dry-run mode only;
- collect machine-readable evidence files.

Not authorized in the first handoff:

- Pulpo production credentials;
- GitHub tokens or cloud credentials;
- network configuration changes;
- SSH key changes;
- GPIO writes;
- relay, motor, camera, microphone, or actuator control;
- persistent daemon or system service installation;
- autostart, cron, launchd, or systemd changes.

The next threshold must be separately authorized: valid permit -> one controlled physical signal; all denial/replay cases -> no physical signal; independent observation -> reconciled.
