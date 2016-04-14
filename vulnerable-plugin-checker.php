<?php 
/*
	Plugin Name: Vulnerable Plugin Checker
	Plugin URI: https://www.eridesignstudio.com/vulnerable-plugin-checker
	Description: Automatically checks installed plugins for known vulnerabilities utilizing WPScan's API and provides optional email alerts.
	Version: 0.1.3
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

add_action('admin_menu', 'vpc_menu');

function vpc_menu() {
	add_submenu_page('tools.php', 'Vulnerable Plugin Checker Settings', 'VPC Settings', 'administrator', 'vpc-settings', 'vpc_settings_page', 'dashicons-admin-generic');
}

function vpc_settings_page() { 
	global $plugins;

	$plugins = vpc_get_installed_plugins_cache();
?>
 
	<div class="wrap">
		<h2>Vulnerable Plugin Checker</h2>

		<form method="post" action="options.php">
		    <?php settings_fields( 'vpc-settings-group' ); ?>
		    <?php do_settings_sections( 'vpc-settings-group' ); ?>
		    <table class="form-table">
		         
		        <tr valign="top">
		        	<th scope="row">Enable Email Alerts</th>
		        <?php if(get_option('vpc_allow_email_alert')) { ?>
		       		<td><input type="checkbox" name="vpc_allow_email_alert" checked /></td>
		       	<?php } else { ?>
		       		<td><input type="checkbox" name="vpc_allow_email_alert" /></td>
		       	<?php } ?>
		        </tr>
		        
		        <tr valign="top">
		       	 <th scope="row">Alert Email Address</th>
		        	<td><input type="text" name="vpc_alert_email" placeholder="Email Address" value="<?php echo esc_attr( get_option('vpc_alert_email') ); ?>" /></td>
		        </tr>

		    </table>
		    
		    <?php submit_button(); ?>
		
		</form>
	</div>

<?php 
}

add_action( 'admin_init', 'vpc_settings' );

function vpc_settings() {
	register_setting( 'vpc-settings-group', 'vpc_allow_email_alert' );
	register_setting( 'vpc-settings-group', 'vpc_alert_email' );
}

function vpc_get_installed_plugins() {
	$plugins = get_plugins();

	$vuln_plugins = array();

	foreach($plugins as $key => $plugin) {
		// if text domain isn't listed get the plugin folder name
		if(empty($plugin['TextDomain'])) {
			$folder_name = explode('/', $key);
			$plugin['TextDomain'] = $folder_name[0];
		}
		
		$plugin['is_known_vulnerable'] = 'false';
		$plugin_vuln = vpc_get_plugin_security_json($plugin['TextDomain']);

		if(is_object($plugin_vuln)) {
			foreach($plugin_vuln->$plugin['TextDomain']->vulnerabilities as $vulnerability) {
				$plugin['vulnerabilities'][] = $vulnerability;

				// if plugin fix is greater than current version, assume it could be vulnerable
				if(version_compare($vulnerability->fixed_in, $plugin['Version']) > 0) {			
					$plugin['is_known_vulnerable'] = 'true';
				}

			}
		}
		
		if(isset($plugin['is_known_vulnerable']) && $plugin['is_known_vulnerable'] == 'true') {	
			$name = $plugin['Name'];
			$vuln_plugins[] = $plugin['Name'];
		}


		$plugin['file_path'] = $key;

		$plugins[$key] = $plugin;
	}

	update_option('vpc-plugin-data', json_encode($plugins));

	// send email if vulnderabilities have been detected
	if(!empty($vuln_plugins) && get_option('vpc_allow_email_alert')) {
		$plugin_url = get_admin_url() . 'plugins.php';
		$vpc_url = get_admin_url() . 'tools.php?page=vpc-settings';
		$message = 'We have detected one or more of your plugins are vulnerable. (' . implode(', ', $vuln_plugins) . '). ' . "\n\n" . 'Please log into your website here: ' . $plugin_url . ' and update your plugins.' .  "\n\n" . 'This message was sent automatically from "Vulnerable Plugin Checker". ' . "\n\n" . 'If you wish to stop recieving emails regarding vulnerabilites, you can disable them in the VPC Settings Page: ' . $vpc_url ;
		$email = get_option('vpc_alert_email');
		if(empty($email)) {
			$email = get_option('admin_email');
		}
		$sent = wp_mail($email, get_option('blogname') . ' - Vulnerability Detected', $message);
	}

	return $plugins;


}

// get cached data so we dont spam their api cause I'm nice
function vpc_get_installed_plugins_cache() {

	$plugin_data = get_option('vpc-plugin-data');
	if(!empty($plugin_data)) {

		$plugins = json_decode(get_option('vpc-plugin-data'), true); 
		$plugins_nc = get_plugins();

		foreach($plugins as $key => $plugin) {

			$plugin['Version'] = $plugins_nc[$key]['Version'];

			if(isset($plugin['vulnerabilities']) && is_array($plugin['vulnerabilities'])) {

				foreach($plugin['vulnerabilities'] as $vulnerability) {

					// if plugin fix is greater than current version, assume it could be vulnerable
					if(version_compare($vulnerability['fixed_in'], $plugin['Version']) > 0) {			
						$plugin['is_known_vulnerable'] = 'true';
						$vuln_plugins[] = $plugin;
					} else {
						$plugin['is_known_vulnerable'] = 'false';
					}

				}

			}
			

			$plugins[$key] = $plugin;
		}
		return $plugins;
	} else {
		// this occurs only right after activation
		vpc_get_installed_plugins();
	}

}

// pull json data from WPVULNDB's API
function vpc_get_plugin_security_json($text_domain) {
	$url = 'https://wpvulndb.com/api/v2/plugins/' . $text_domain;

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	$data = curl_exec($ch);
	curl_close($ch);

	return json_decode($data);
}

add_action('admin_head-plugins.php','vpc_get_plugins_admin_head');
function vpc_get_plugins_admin_head() {

	$plugins = vpc_get_installed_plugins_cache();

	// kinda crappy fix till I figure the issue
	if(!is_array($plugins)) {
		$plugins = vpc_get_installed_plugins_cache();
	}

	// vulnerable text display
	function vpc_after_row_text( $plugin_file, $plugin_data, $status ) {
		echo '<tr class="active update">
				<td style="border-left: 4px solid #d54e21; border-bottom: 1px solid #E2E2E2;">&nbsp;</td>
				<td colspan="2" style="border-bottom: 1px solid #E2E2E2; color: #D54E21; font-weight: 600;">
	        		' . $plugin_data['Name'] . ' has a known vulnerability that may be affecting this version. Please update this plugin. <a target="_blank" href="https://wpvulndb.com/search?utf8=✓&text=' . $plugin_data['Name'] . '">View Vulnerabilities</a>
	        	</td>
	    	</tr>';
	}

	// add after plugin row text
	foreach($plugins as $plugin) {
		$path = $plugin['file_path'];

		if(isset($plugin['is_known_vulnerable']) && $plugin['is_known_vulnerable'] == 'true') {

			add_action("after_plugin_row_{$path}", 'vpc_after_row_text', 10, 3 );

		}
		
	}

}

// add option & task on activation
register_activation_hook(__FILE__, 'vpc_on_activation');
add_action('vpc_pull_db_data_event', 'vpc_get_installed_plugins');

function vpc_on_activation() {
	if(!get_option('vpc-plugin-data')) {
		add_option('vpc-plugin-data', '');
	}

	wp_schedule_event(time(), 'twicedaily', 'vpc_pull_db_data_event');
}


// remove task & option on deactivation
register_deactivation_hook(__FILE__, 'vpc_on_deactivation');

function vpc_on_deactivation() {
	delete_option('vpc-plugin-data');
	wp_clear_scheduled_hook('vpc_pull_db_data_event');
}

add_filter('wp_mail_from','vpc_wp_mail_from');
function vpc_wp_mail_from($content_type) {
	return get_option('admin_email');
}

// add settings to plugin page
function add_vpc_settings_link ( $links ) {
    $links[] = '<a href="' . admin_url( 'tools.php?page=vpc-settings' ) . '">Settings</a>';
    return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'add_vpc_settings_link' );


?>