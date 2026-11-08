# Airtel Wi-Fi Network Access Manager

This repository contains the dashboard and local Python proxy for the TYRAX3004H router.

## Running locally

1. Start the proxy from this folder:
   python wifi_proxy.py
2. Open http://localhost:8080/index.html
3. Enter the router management password in the dashboard.

The password is only held in the proxy process and is not saved by the application.

## GitHub Pages

GitHub Pages can host the `index.html` interface, but router administration still requires the Python proxy running inside the same trusted local network. GitHub-hosted pages cannot securely access the private router APIs directly. Keep the proxy listening on localhost and use the local dashboard URL for live management.
