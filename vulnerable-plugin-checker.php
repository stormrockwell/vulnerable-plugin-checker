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
			add_action( 'admin_head-plugins.php', array( $this, 'get_plugins_admin_head' ) );

			register_activation_hook( __FILE__, array( $this, 'on_activation' ) );
			add_action( 'vpc_pull_db_data_event', array( $this, 'get_installed_plugins' ) );

			register_deactivation_hook( __FILE__, array( $this, 'on_deactivation' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_settings_link' ) );

			add_action( 'activated_plugin', array( $this, 'on_any_plugin_activation' ), 10, 2 );
		}

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

		public function set_text_domain( $plugin ) {

			// get text domain from folder if it isn't listed
			if ( empty( $plugin['TextDomain'] ) ) {
				$folder_name = explode( '/', $key );
				$plugin['TextDomain'] = $folder_name[0];
			}

			return $plugin;

		}

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
			if ( ! empty( $vuln_plugins ) && get_option( 'vpc_allow_email_alert' ) ) {

				$plugin_url = get_admin_url() . 'plugins.php';
				$vpc_url = get_admin_url() . 'tools.php?page=vpc-settings';
				$message = 'We have detected one or more of your plugins are vulnerable. (' . implode( ', ', $vuln_plugins ) . '). ' . "\n\n" . 'Please log into your website here: ' . $plugin_url . ' and update your plugins.' .  "\n\n" . 'This message was sent automatically from "Vulnerable Plugin Checker". ' . "\n\n" . 'If you wish to stop recieving emails regarding vulnerabilites, you can disable them in the VPC Settings Page: ' . $vpc_url;
				$email = get_option( 'admin_email' );

				wp_mail( $email, get_option( 'blogname' ) . ' - Vulnerability Detected', $message );

			}

			return $plugins;

		}

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

		public function get_plugins_admin_head() {

			$plugins = $this->get_installed_plugins();

			// add after plugin row text
			foreach ( $plugins as $plugin ) {

				$path = $plugin['file_path'];

				if ( isset( $plugin['is_known_vulnerable'] ) &&  'true' == $plugin['is_known_vulnerable'] ) {
					add_action( 'after_plugin_row_' . $path, array( $this, 'after_row_text' ), 10, 3 );
				}	

			}

		}

		public function after_row_text( $plugin_file, $plugin_data, $status ) {

			$string  = '<tr class="active update">';
			$string .=    '<td style="border-left: 4px solid #d54e21; border-bottom: 1px solid #E2E2E2;">&nbsp;</td>';
			$string .=    '<td colspan="2" style="border-bottom: 1px solid #E2E2E2; color: #D54E21; font-weight: 600;">'; 
			$string .=       $plugin_data['Name'] . ' has a known vulnerability that may be affecting this version. Please update this plugin. <a target="_blank" href="https://wpvulndb.com/search?utf8=✓&text=' . $plugin_data['Name'] . '">View Vulnerabilities</a>';
			$string .=    '</td>';
			$stirng .= '</tr>';

			echo $string;

		}

		public function on_activation() {

			if ( ! get_option( 'vpc-plugin-data' ) ) {
				add_option( 'vpc-plugin-data', '' );
			}

			wp_schedule_event( time(), 'twicedaily', 'vpc_pull_db_data_event' );

		}

		public function on_deactivation() {
			delete_option( 'vpc-plugin-data' );
			wp_clear_scheduled_hook( 'vpc_pull_db_data_event' );
		}

		public function add_settings_link( $links ) {
		    $links[] = '<a href="' . admin_url( 'tools.php?page=vpc-settings' ) . '">Settings</a>';
		    return $links;
		}

		// on any plugin activation
		// TODO: only run if VPC isn't activated
		// TODO: Only run for a single plguin
		public function on_any_plugin_activation( $plugin, $network_activation ) {
		    $this->get_installed_plugins();
		}

	}

	$vulnerable_plugin_checker = new Vulnerable_Plugin_Checker;