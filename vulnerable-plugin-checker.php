<?php 
	/*
		Plugin Name: Vulnerable Plugin Checker
		Plugin URI: https://www.eridesignstudio.com/vulnerable-plugin-checker
		Description: Automatically checks installed plugins for known vulnerabilities utilizing WPScan's API and provides optional email alerts.
		Version: 0.3.11
		Author: Storm Rockwell
		Author URI: http://www.stormrockwell.com
		License: GPL2v2
		
		Vulnerable Plugin Checker is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 2 of the License, or
		any later version.
		 
		Vulnerable Plugin Checker is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
		GNU General Public License for more details.
		 
		You should have received a copy of the GNU General Public License
		along with Vulnerable Plugin Checker. If not, see https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html.
	*/


	class Vulnerable_Plugin_Checker {
		public $title;
		public $menu_title;
		public $api_url = 'https://wpvulndb.com/api/v2/plugins/';

		/**
		 * Constructor
		 */
		public function __construct() {
			$this->title = __( 'Vulnerable Plugin Checker', 'vulnerable-plugin-checker' );
			$this->menu_title = __( 'VPC Settings', 'vulnerable-plugin-checker' );

			add_action( 'admin_head', array( $this, 'admin_head' ) );

			register_activation_hook( __FILE__, array( $this, 'on_activation' ) );
			add_action( 'vpc_pull_db_data_event', array( $this, 'get_installed_plugins' ) );

			register_deactivation_hook( __FILE__, array( $this, 'on_deactivation' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_settings_link' ) );

			add_action( 'activated_plugin', array( $this, 'get_installed_plugins' ), 10, 2 );
			add_action( 'upgrader_process_complete', array( $this, 'get_installed_plugins' ), 10, 2 );

			add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );

			add_action( 'admin_init', array( $this, 'register_fields' ) );
		}

		/**
		 * Register Fields
		 * register backend fields for the settings page
		 */
		public function register_fields() {
			register_setting( 'vpc-settings-group', 'vpc_email_address' );
			register_setting( 'vpc-settings-group', 'vpc_allow_emails' );
		}

		/**
		 * Add Menu Pages
		 * adds menu/submenu pages to the dashboard
		 */
		public function add_menu_pages() {
			add_submenu_page( 'options-general.php', $this->title, $this->menu_title, 'manage_options', 'vpc-settings', array( $this, 'settings_page' ) );
		}

		/**
		 * Settings Page
		 * dashboard page to manage settings
		 */
		public function settings_page() {

			$allow_emails_checked = get_option( 'vpc_allow_emails' ) ? 'checked' : '';

			$string  = '<div class="wrap">';
			$string .=    '<h2>' . $this->title . ' Settings</h2>';
			$string .=    '<form method="post" action="options.php">';

			// need to echo because there is no get_settings_field
			echo $string;

			settings_fields( 'vpc-settings-group' );
			do_settings_sections( 'vpc-settings-group' );

			// restart string
			$string  =       '<p>';
			$string .=          sprintf( 
									/* translators: %s: admin url for wp mail smtp plugin */
									__( 'Please use an SMTP plugin such as <a href="%s">WP Mail SMTP</a> to prevent dropped emails.', 'vulnerable-plugin-checker' ),
									admin_url( 'plugin-install.php?s=wp+mail+smtp&tab=search&type=term' )
								);
			$string .=       '</p>';
			$string .=       '<table class="form-table">';
			$string .=          '<tr valign="top">';
			$string .=             '<th scope="row">' . __( 'Email Address:', 'vulnerable-plugin-checker' ) . '</th>';
			$string .=             '<td>';
			$string .=                '<input type="text" name="vpc_email_address" placeholder="' . esc_attr( get_option( 'admin_email' ) ) . '" value="' . esc_attr( get_option( 'vpc_email_address' ) ) . '" />';
			$string .=             '</td>';
			$string .=          '</tr>';
			$string .=          '<tr valign="top">';
			$string .=             '<th scope="row">' . __( 'Allow Email Alerts:', 'vulnerable-plugin-checker' ) . '</th>';
			$string .=             '<td>';
			$string .=                '<input type="checkbox" name="vpc_allow_emails" ' . $allow_emails_checked . ' />';
			$string .=             '</td>';
			$string .=          '</tr>';
			$string .=       '</table>';
			$string .=        get_submit_button();
			$string .=    '</form>';
			$string .= '</div>';

			echo $string;
			
		}

		/**
		 * Get Cached Plugin Vulnerabilities
		 * pulls installed plugins, compares version to cached vulnerabilities, adds is_known_vulnerable key to plugin.
		 * @param  array  $plugin    
		 * @param  string $file_path plugin file path
		 * @return array             updated plugin array
		 */
		public function get_cached_plugin_vulnerabilities( $plugin, $file_path ) {

			global $installed_plugins;

			// TODO: convert to cached installed plugins
			if ( ! is_array( $installed_plugins ) ) {

				if ( ! function_exists( 'get_plugins' ) ) {
			        require_once ABSPATH . 'wp-admin/includes/plugin.php';
			    }

				$installed_plugins = get_plugins();
			}

			$plugin = $this->set_text_domain( $plugin );

			if ( isset( $installed_plugins[ $file_path ]['Version'] ) ) {

				// updated the cached version with the one taken from the currently installed
				$plugin['Version'] = $installed_plugins[ $file_path ]['Version'];

				if ( isset( $plugin['vulnerabilities'] ) && is_array( $plugin['vulnerabilities'] ) ) {

					foreach ( $plugin['vulnerabilities'] as $vulnerability ) {

						// if plugin fix is greater than current version, assume it could be vulnerable
						$plugin['is_known_vulnerable'] = 'false';
						if ( null == $vulnerability['fixed_in'] || version_compare( $vulnerability['fixed_in'], $plugin['Version'] ) > 0 ) {			
							$plugin['is_known_vulnerable'] = 'true';
						}

					}

				}

			}

			$plugin['file_path'] = $file_path;

			return $plugin;

		}

		/**
		 * Get Fresh Plugin Vulnerabilities
		 * pull vulnerabilities through API, compare version to vulnerabilities, add is_know_vulnerable key
		 * @param  array  $plugin
		 * @param  string $file_path plugin file path
		 * @return array             updated plugin
		 */
		public function get_fresh_plugin_vulnerabilities( $plugin, $file_path ) {	

			$plugin = $this->set_text_domain( $plugin );
			$text_domain = $plugin['TextDomain'];
			$plugin_vuln = $this->get_plugin_security_json( $text_domain );

			if ( is_object( $plugin_vuln ) && property_exists( $plugin_vuln, $text_domain ) && is_array( $plugin_vuln->$text_domain->vulnerabilities ) ) {

				foreach ( $plugin_vuln->$text_domain->vulnerabilities as $vulnerability ) {

					$plugin['vulnerabilities'][] = $vulnerability;

					// if plugin fix is greater than current version, assume it could be vulnerable
					$plugin['is_known_vulnerable'] = 'false';
					if ( null == $vulnerability->fixed_in || version_compare( $vulnerability->fixed_in, $plugin['Version'] ) > 0 ) {			
						$plugin['is_known_vulnerable'] = 'true';
					}

				}

			}

			$plugin['file_path'] = $file_path;

			return $plugin;

		}

		/**
		 * Set Text Domain
		 * sets the text domain to the TextDomain key if it is not set
		 * @param  array $plugin
		 * @return array          updated plugin
		 */
		public function set_text_domain( $plugin ) {

			// get text domain from folder if it isn't listed
			if ( empty( $plugin['TextDomain'] ) && isset( $plugin['file_path'] ) ) {
				$folder_name = explode( '/', $plugin['file_path'] );
				$plugin['TextDomain'] = $folder_name[0];
			}

			return $plugin;

		}

		/**
		 * Get Installed Plugins
		 * gets the installed plugins, checks for vulnerabilities in them, caches the data, sends email if vulnerabilities detected
		 * @return array installed plugins with vulnerability data
		 */
		public function get_installed_plugins( $email = true ) {

			if ( ! function_exists( 'get_plugins' ) ) {
		        require_once ABSPATH . 'wp-admin/includes/plugin.php';
		    }

			$plugins = get_plugins();
			$vuln_plugins = array();

			foreach ( $plugins as $key => $plugin ) {

				$plugin = $this->get_fresh_plugin_vulnerabilities( $plugin, $key );
				$plugins[ $key ] = $plugin;
			
				if ( isset( $plugin['is_known_vulnerable'] ) && 'true' == $plugin['is_known_vulnerable'] ) {	
					$name = $plugin['Name'];
					$vuln_plugins[] = $plugin['Name'];
				}

			}

			update_option( 'vpc-plugin-data', json_encode( $plugins ) );

			// send email if vulnderabilities have been detected
			if ( ! empty( $vuln_plugins ) && $email && get_option( 'vpc_allow_emails' ) ) {

				$plugins_url = get_admin_url( null, 'plugins.php' );
				$vpc_url = get_admin_url( null, 'options-general.php?page=vpc-settings' );

				$message = sprintf(
								/* translators: 1: plugins url, 2: Vulnerable Plugin Checker, 3: Vulnerable Plugin Checker url */
								__( 'We have detected one or more of your plugins are vulnerable.' . "\n\n" . 'Please log into your website here: %1$s and update your plugins.' . "\n\n" . 'This message was sent automatically from %2$s.' . "\n\n" . 'If you wish to stop recieving emails regarding vulnerabilites, you can disable them in the VPC Settings Page: %3$s', 'vulnerable-plugin-checker' ),
								$plugins_url,
								$this->title,
								$vpc_url
							);

				$subject = sprintf(
								/* translators: %s: blog name */
								__( '%s - Vulnerability Detected', 'vulnerable-plugin-checker' ),
								get_bloginfo( 'blogname' )
							);

				$to = get_option( 'vpc_email_address' );
				if ( ! isset( $to ) ) {
					$to = get_option( 'admin_email' );
				}

				wp_mail( $to, $subject, $message );

			}

			return $plugins;

		}

		/**
		 * Get Installed Plugins Cache
		 * gets the installed plugins, checks for vulnerabilities with cached results
		 * @return array installed plugins with vulnerability data
		 */
		public function get_installed_plugins_cache() {

			$plugin_data = json_decode( get_option( 'vpc-plugin-data' ) );
			if ( ! empty( $plugin_data ) ) {

				if ( ! function_exists( 'get_plugins' ) ) {
			        require_once ABSPATH . 'wp-admin/includes/plugin.php';
			    }

				$plugins = json_decode( get_option( 'vpc-plugin-data' ), true );

				foreach ( $plugins as $key => $plugin ) {
					$plugin = $this->get_cached_plugin_vulnerabilities( $plugin, $key );
					$plugins[ $key ] = $plugin;
				}

				return $plugins;
				
			} else {
				// this occurs only right after activation
				$this->get_installed_plugins();
			}

		}

		/**
		 * Get Plugin Security JSON
		 * gets data from the vulnerability database and returns the result in JSON
		 * @param  string $text_domain plugin text domain
		 * @return string              json string of vulnerabilities for the given text domain
		 */
		public function get_plugin_security_json( $text_domain ) {

			$url = $this->api_url . $text_domain;
			$request = wp_remote_get( $url, array( 'sslverify' => false ) );

			if ( is_wp_error( $request ) ) {
			    return false;
			}

			$body = wp_remote_retrieve_body( $request );

			return json_decode( $body );

		}

		/**
		 * Admin Head
		 * gets installed plugins cache, adds after row text and notices based on the results for the plugin page
		 * @return null
		 */
		public function admin_head() {
			global $pagenow;

			$plugins = $this->get_installed_plugins_cache();

			// add after plugin row text
			foreach ( $plugins as $plugin ) {

				$path = $plugin['file_path'];
				$added_notice = false;

				if ( isset( $plugin['is_known_vulnerable'] ) &&  'true' == $plugin['is_known_vulnerable'] ) {
					add_action( 'after_plugin_row_' . $path, array( $this, 'after_row_text' ), 10, 3 );

					if ( ! $added_notice ) {
						add_action( 'admin_notices', array( $this, 'vulnerable_admin_notice' ) );
						$added_notice = true;
					}
				}	

			}

		}

		/**
		 * Vulnerable Admin Notice
		 * prints out error message if plugin(s) is/are vulnerable
		 */
		public function vulnerable_admin_notice() {
			$class = 'notice notice-error is-dismissible';
			$message = __( '<strong>VPC:</strong> One or more plugins currently installed have known vulnerabilities with their current version. I suggest updating each vulnerable plugin if an update is available', 'vulnerable-plugin-checker' );

			printf( '<div class="%1$s"><p>%2$s</p></div>', $class, $message ); 
		}

		/**
		 * After Row Text
		 * callback function for adding vulnerability notice under vulnerable plugins
		 * @param  string $plugin_file main plugin folder/file_name
		 * @param  array  $plugin_data
		 */
		public function after_row_text( $plugin_file, $plugin_data, $status ) {

			global $vpc_plugin_data;

			if ( ! is_array( $vpc_plugin_data ) ) {
				$vpc_plugin_data = json_decode( get_option( 'vpc-plugin-data' ), true );
			}

			$message =  sprintf(
							/* translators: 1: plugin name */ 
							__( '%1$s has a known vulnerability that may be affecting this version. Please update this plugin.', 'vulnerable-plugin-checker' ), 
							$plugin_data['Name'] 
						);

			$string  = '<tr class="active update">';
			$string .=    '<td style="border-left: 4px solid #d54e21; border-bottom: 1px solid #E2E2E2;">&nbsp;</td>';
			$string .=    '<td colspan="2" style="border-bottom: 1px solid #E2E2E2; color: #D54E21;">'; 
			$string .=       '<p style="color: #D54E21"><strong>' . $message . '</strong></p>';
			
			$string .=       '<table>';

			$vulnerabilities = $this->get_cached_plugin_vulnerabilities( $vpc_plugin_data[ $plugin_file ], $plugin_file );
			foreach ( $vulnerabilities['vulnerabilities'] as $vulnerability ) {

				if ( null == $vulnerability['fixed_in'] || $vulnerability['fixed_in'] > $plugin_data['Version'] ) {

					$fixed_in = '';
					if ( null !== $vulnerability['fixed_in'] ) {
						$fixed_in = sprintf( 
										/* translators: %s: plugin version number */
										__( 'Fixed in version: %s' ), 
										$vulnerability['fixed_in'] 
									);
					}

					$string .=       '<tr>';
					$string .=          '<td style="padding: 4px 15px 4px 0;"><strong>' . $vulnerability['title'] . '</strong></td>';
					$string .=          '<td style="padding: 4px 15px 4px 0;">' . $fixed_in . '</td>';
					$string .=       '</tr>';

				}

			}

			$string .=       '</table>';

			$string .=    '</td>';
			$string .= '</tr>';

			echo $string;

		}

		/**
		 * On Activation
		 * callback function for when the plugin is activated
		 * add plugin data option if it isn't created already, schedule wp-cron job
		 */
		public function on_activation() {

			if ( ! get_option( 'vpc-plugin-data' ) ) {
				add_option( 'vpc-plugin-data', '' );
			}

			if ( ! get_option( 'vpc_allow_emails' ) ) {
				add_option( 'vpc_allow_emails', 1 );
			}

			wp_schedule_event( time(), 'twicedaily', 'vpc_pull_db_data_event' );

			$this->get_installed_plugins( false );

		}

		/**
		 * On Deactivation
		 * callback function when a plugin is deactivated
		 * delete, option and remove wp-cron job
		 */
		public function on_deactivation() {
			delete_option( 'vpc-plugin-data' );
			wp_clear_scheduled_hook( 'vpc_pull_db_data_event' );
		}

		/**
		 * Add Settings Link
		 * @param array $links links that appear in the plugin row
		 */
		public function add_settings_link( $links ) {
		    $links[] = '<a href="' . get_admin_url( null, 'options-general.php?page=vpc-settings' ) . '">Settings</a>';
		    return $links;
		}

	}

	$vulnerable_plugin_checker = new Vulnerable_Plugin_Checker;