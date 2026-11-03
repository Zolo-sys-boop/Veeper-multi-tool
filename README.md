# VESPER

Recon multitool for Ubuntu. Terminal UI, twelve modules, no cloud.

Made by Zolo.

`vesper` puts the things you keep doing by hand — sweeping a subnet, checking what answered, pulling a cert, hashing a file, grading TLS — behind one menu with a target you set once.

![status](https://img.shields.io/badge/status-active-brightgreen)

## What it is

A single Python file. Stdlib only for the core. External tools are optional and it degrades gracefully when they're missing.

Indicators, not proof. A finding means "worth a look", not "compromised".

## Install

Ubuntu 22.04 or newer. Python 3.10+.

```bash
git clone https://github.com/Zolo-sys-boop/vesper.git
cd vesper
chmod +x vesper.py
