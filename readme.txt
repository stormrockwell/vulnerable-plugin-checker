=== Vulnerable Plugin Checker ===
Contributors: stormrockwell
Tags: vulnerable,vulnerability,plugin,plugins,checker,scanner,wpscan,wpvulndb,security
Requires at least: 4.0
Tested up to: 4.7
Stable tag: 0.3.11
License: GPLv2
License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

Automatically checks installed plugins for known vulnerabilities and provides optional email alerts.

== Description ==

This plugin automatically checks installed plugins for known vulnerabilities utilizing WPScan's API and provides optional email alerts.

**Features:**

* Automatic vulnerability detection in plugins utilizing WPScan's API
* Optional email alerts
* Utilizes WP Cron to check for new security updates twice a day
* Cached API results to decrease backend load time significantly

== Installation ==

**Installation & Activation**

1. Upload the folder "vulnerable-plugin-checker" to your WordPress Plugins Directory (typically "/wp-content/plugins/")
2. Activate the plugin on your Plugins Page.
3. Suggestion: Install an SMTP plugin such as WP Mail SMTP to prevent potentially dropped emails
3. Done!

**Enable Email Updates**

1. After activating "Vulnerable Plugin Checker", go to Settings > VPC Settings
2. Check off "Allow Email Alerts" and enter your email in "Email Address"
3. Click Save Changes


== Screenshots ==

1. Backend display of the Plugins page (plugins.php)
2. Backend display of the VPC Settings page (Settings > VPC Settings)

== Changelog ==

= 0.3.11 =

- Now it only shows only vulnerabilities that affect the current plugin version

= 0.3.10 =

- Fixed bug where unpatched vulnerabilities were ignored (thank you @pluginvulnerabilities for finding the bug)

= 0.3.9 =

- Fixed notice appearing on PHP7+

= 0.3.8 =

- fixed bug where it wouldn't display the saved email

= 0.3.7 =

- removed sslverify on wp_remote_get

= 0.3.6 =

- changed cURL to wp_remote_get
- added vulnerabilities on plugin page
- fixed issue with plugin not pulling from cache

= 0.3.5 =

- fixed readme error

= 0.3.4 =

- fixed minor email bug

= 0.3.2 =

- changed language

= 0.3 =

- Rewrote the plugin for better performance, readability, and more
- Dismissable error message in all back-end pages if there is a vulnerability
- Added SMTP suggestion to prevent dropped emails
- Removed success notice from plugin page if there are no vulnerabilities
- Fixed a few non-breaking bugs
- Added translatable text and translator comments. Translation help is welcome!
- Added todo.txt to see my plans for future updates.

= 0.2.4 =

- Fixed conflicts with Gravity Forms

= 0.2.3 =

- Added support for adding multiple email addresses

= 0.2.2 =

- Fixed issue where text display appeared on multiple backend pages

= 0.2 =

- Text display on the plugins page if there are no known vulnerabilities
- Runs a scan when a new plugin is activated
- Fixed issue when a plugin was deleted it would throw an error

= 0.1.4 =

- WP 4.5 Support

= 0.1.3 =

- Fixed issue when more than one plugin was found vulnerable on plugins.php


