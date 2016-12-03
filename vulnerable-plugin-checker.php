<?php 
	/*
		Plugin Name: Vulnerable Plugin Checker
		Plugin URI: https://www.eridesignstudio.com/vulnerable-plugin-checker
		Description: Automatically checks installed plugins for known vulnerabilities utilizing WPScan's API and provides optional email alerts.
		Version: 0.2.4
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
		public $title = 'Vulnerable Plugin Checker';
		public $api_url = 'https://wpvulndb.com/api/v2/plugins/';

		/**
		 * Constructor
		 */
		public function __construct() {
			add_action( 'admin_head-plugins.php', array( $this, 'plugins_page_admin_head' ) );

			register_activation_hook( __FILE__, array( $this, 'on_activation' ) );
			add_action( 'vpc_pull_db_data_event', array( $this, 'get_installed_plugins' ) );

			register_deactivation_hook( __FILE__, array( $this, 'on_deactivation' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_settings_link' ) );

			add_action( 'activated_plugin', array( $this, 'get_installed_plugins' ), 10, 2 );
			add_action( 'upgrader_process_complete', array( $this, 'get_installed_plugins' ), 10, 2 );
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
				$installed_plugins = get_plugins();
			}

			$plugin = $this->set_text_domain( $plugin );

			if ( isset( $installed_plugins[ $file_path ]['Version'] ) ) {

				$plugin['Version'] = $installed_plugins[ $file_path ]['Version'];

				if ( isset( $plugin['vulnerabilities'] ) && is_array( $plugin['vulnerabilities'] ) ) {

					foreach ( $plugin['vulnerabilities'] as $vulnerability ) {

						// if plugin fix is greater than current version, assume it could be vulnerable
						$plugin['is_known_vulnerable'] = 'false';
						if ( version_compare( $vulnerability['fixed_in'], $plugin['Version'] ) > 0 ) {			
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
			$plugin_vuln = $this->get_plugin_security_json( $plugin['TextDomain'] );

			if ( is_object( $plugin_vuln ) && isset( $plugin_vuln->$plugin['TextDomain']->vulnerabilities ) ) {

				foreach ( $plugin_vuln->$plugin['TextDomain']->vulnerabilities as $vulnerability ) {

					$plugin['vulnerabilities'][] = $vulnerability;

					// if plugin fix is greater than current version, assume it could be vulnerable
					$plugin['is_known_vulnerable'] = 'false';
					if ( version_compare( $vulnerability->fixed_in, $plugin['Version'] ) > 0 ) {			
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
			if ( empty( $plugin['TextDomain'] ) ) {
				$folder_name = explode( '/', $key );
				$plugin['TextDomain'] = $folder_name[0];
			}

			return $plugin;

		}

		/**
		 * Get Installed Plugins
		 * gets the installed plugins, checks for vulnerabilities in them, caches the data, sends email if vulnerabilities detected
		 * @return array installed plugins with vulnerability data
		 */
		public function get_installed_plugins() {

			$plugins = get_plugins();
			$vuln_plugins = array();

			foreach ( $plugins as $key => $plugin ) {

				$plugin = $this->get_fresh_plugin_vulnerabilities( $plugin, $key );
				$plugins[ $key ] = $plugin;
			
				if ( isset( $plugin['is_known_vulnerable'] ) && $plugin['is_known_vulnerable'] == 'true' ) {	
					$name = $plugin['Name'];
					$vuln_plugins[] = $plugin['Name'];
				}

			}

			update_option( 'vpc-plugin-data', json_encode( $plugins ) );

			// send email if vulnderabilities have been detected
			if ( ! empty( $vuln_plugins ) ) {

				$plugin_url = get_admin_url() . 'plugins.php';
				$vpc_url = get_admin_url() . 'tools.php?page=vpc-settings';
				$message = 'We have detected one or more of your plugins are vulnerable. (' . implode( ', ', $vuln_plugins ) . '). ' . "\n\n" . 'Please log into your website here: ' . $plugin_url . ' and update your plugins.' .  "\n\n" . 'This message was sent automatically from "Vulnerable Plugin Checker". ' . "\n\n" . 'If you wish to stop recieving emails regarding vulnerabilites, you can disable them in the VPC Settings Page: ' . $vpc_url;
				$email = get_option( 'admin_email' );

				wp_mail( $email, get_option( 'blogname' ) . ' - Vulnerability Detected', $message );

			}

			return $plugins;

		}

		/**
		 * Get Installed Plugins Cache
		 * gets the installed plugins, checks for vulnerabilities with cached results
		 * @return array installed plugins with vulnerability data
		 */
		public function get_installed_plugins_cache() {

			$plugin_data = get_option( 'vpc-plugin-data' );
			if ( ! empty( $plugin_data ) ) {

				$plugins = json_decode( get_option( 'vpc-plugin-data' ), true ); 
				$installed_plugins = get_plugins();

				foreach ( $plugins as $key => $plugin ) {
					$plugin = $this->get_fresh_plugin_vulnerabilities( $plugin, $key );
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

			$ch = curl_init();
			curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt( $ch, CURLOPT_URL, $url );
			curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
			curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 6 );
			$data = curl_exec( $ch );
			curl_close( $ch );

			return json_decode( $data );

		}

		/**
		 * Plugins Page Admin Head
		 * gets installed plugins cache, adds after row text and notices based on the results for the plugin page
		 * @return null
		 */
		public function plugins_page_admin_head() {

			$plugins = $this->get_installed_plugins_cache();

			// add after plugin row text
			foreach ( $plugins as $plugin ) {

				$path = $plugin['file_path'];

				if ( isset( $plugin['is_known_vulnerable'] ) &&  'true' == $plugin['is_known_vulnerable'] ) {
					add_action( 'after_plugin_row_' . $path, array( $this, 'after_row_text' ), 10, 3 );

					if ( ! $added_notice ) {
						add_action( 'admin_notices', array( $this, 'vulnerable_admin_notice' ) );
					}
				}	

			}

		}

		/**
		 * Vulnerable Admin Notice
		 * prints out error message if plugin(s) is/are vulnerable
		 */
		public function vulnerable_admin_notice() {
			$class = 'notice notice-error';
			$message = __( '<strong>VPC:</strong> One or more plugins currently installed have known vulnerabilities with their current version. I suggest updating each vulnerable plugin if an update is available', 'sample-text-domain' );

			printf( '<div class="%1$s"><p>%2$s</p></div>', $class, $message ); 
		}

		/**
		 * After Row Text
		 * callback function for adding vulnerability notice under vulnerable plugins
		 * @param  string $plugin_file main plugin folder/file_name
		 * @param  array  $plugin_data
		 */
		public function after_row_text( $plugin_file, $plugin_data, $status ) {

			$string  = '<tr class="active update">';
			$string .=    '<td style="border-left: 4px solid #d54e21; border-bottom: 1px solid #E2E2E2;">&nbsp;</td>';
			$string .=    '<td colspan="2" style="border-bottom: 1px solid #E2E2E2; color: #D54E21; font-weight: 600;">'; 
			$string .=       $plugin_data['Name'] . ' has a known vulnerability that may be affecting this version. Please update this plugin. <a target="_blank" href="https://wpvulndb.com/search?utf8=✓&text=' . $plugin_data['Name'] . '">View Vulnerabilities</a>';
			$string .=    '</td>';
			$stirng .= '</tr>';

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

			wp_schedule_event( time(), 'twicedaily', 'vpc_pull_db_data_event' );

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
		    $links[] = '<a href="' . admin_url( 'tools.php?page=vpc-settings' ) . '">Settings</a>';
		    return $links;
		}

	}

	$vulnerable_plugin_checker = new Vulnerable_Plugin_Checker;