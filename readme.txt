=== Vulnerable Plugin Checker ===
Contributors: stormrockwell
Tags: vulnerable,vulnerability,plugin,plugins,checker,scanner,wpscan,wpvulndb,security
Requires at least: 4.0
Tested up to: 4.4
Stable tag: 0.1.3
License: GPLv2
License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

Automatically checks installed plugins for known vulnerabilities and provides optional email alerts.


== Description ==

This plugin automatically checks installed plugins for known vulnerabilities utilizing WPScan's API and provides optional email alerts.

**Features:**

* Automatic vulnerability detection in plugins utilizing WPScan's API
* Optional email alerts
* Utilizes WP Cron to check for new security updates twice a day
* Cached API results to increase backend load time significantly

== Installation ==

**Installation & Activation**

1. Upload the folder "vulnerable-plugin-checker" to your WordPress Plugins Directory (typically "/wp-content/plugins/")
2. Activate the plugin on your Plugins Page.
3. Done!

**Enable Email Updates**

1. After activating "Vulnerable Plugin Checker", go to Tools > VPC Settings
2. Check off "Enable Email Alerts" and enter your email in "Alert Email Address"
3. Click Save Changes


== Screenshots ==

1. Backend display of the Plugins page (plugins.php)
2. Backend display of the VPC Settings page (Tools > VPC Settings)

== Changelog ==

= 0.1.3 =

- Fixed issue when more than one plugin was found vulnerable on plugins.php


