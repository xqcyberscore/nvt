##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unprotected_web_app_installers.nasl 9743 2018-05-07 11:15:13Z cfischer $
#
# Unprotected Web App Installers (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107307");
  script_version("$Revision: 9743 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-07 13:15:13 +0200 (Mon, 07 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-07 12:00:20 +0200 (Mon, 07 May 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("Unprotected Web App Installers (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "sw_magento_detect.nasl", "secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80 );
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify installation pages of various
  Web Apps that are publicly accessible and not protected by account restrictions.");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if unprotected
  Web Apps are accessible for installation.");

  script_tag(name:"impact", value:"It is possible to install or reconfigure the software. In doing so,
  the attacker could overwrite existing configurations. It could be possible for the attacker to gain
  access to the base system");

  script_tag(name:"solution", value:"Setup and/or installation pages for Web Apps should not be
  publicly accessible via a web server. Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(600);

  exit(0);
}
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# nb: We can't save an array within an array so we're using:
# array index = the file to check
# array value = the description and the regex of the checked file separated with #-#. Optional a third entry separated by #-# containing an "extra_check" for http_vuln_check()

genericfiles = make_array(
"/index.php", 'Installer /Setup-Tool of multiple vendors.#-#<title>((Microweber|phpipam) installation|Installation|WackoWiki Installation|(Piwik|Matomo) .* &rsaquo; Installation|LimeSurvey installer)</title>#-#',
"/index.php?module=Users&parent=Settings&view=SystemSetup", 'VTiger CMS Installation tool.#-#<title>Install</title> #-#',
"/index.php/index/install", 'Open Journal Systems Installer.#-#<title>O(JS|MP) Installation</title>#-#',
"/index.php/install/", 'Magento and other Installers.#-#<title>(Magento|XLRstats) Installation</title>#-#',
"/install.php", 'Installer / Setup-Tool of multiple vendors.#-#<title>((Moodle|PHP-Fusion) Install|Piwigo * - Installation|Monstra :: Install|Kohana Installation|SMF Installer|vtiger CRM .* - Configuration Wizard - Welcome)</title>#-#',
"/setup.php", 'Installer / Setup-Tool of multiple versions of Zabbix.#-#<title>Installation</title>|class="setup_wizard setup_wizard_welcome"|Check of pre-requisites#-#',
"/tiki-install.php", 'Tiki wiki cms groupware installer.#-#<title>Tiki Installer</title>#-#',
"/admin/install", 'Orchestra Platform installer.#-#<title>Installer &mdash; Orchestra Platform</title>#-#',
"/admin#/mode", 'NetIQ Web Installer#-#<title>Installation</title>#-#',
"/cb_install/", 'ClipBucket installer.#-#<title>ClipBucket .* Installer</title>#-#',
"/centreon/install/setup.php", 'Centreon monitoring tool installer.#-#<title>Centreon Installation</title>#-#',
"/contao/install.php", 'Contao OpenSource CMS Installer.#-#(GNU GENERAL PUBLIC LICENSE|enter a password to prevent)#-#',
"/contao/install", 'Contao OpenSource CMS Installer.#-#GNU GENERAL PUBLIC LICENSE#-#',
"/farcry/core/webtop/install/index.cfm", 'FraCry Core Installer#-#<title>FarCry Core Installer</title>#-#',
"/Install", 'Installer / Setup-Tool of multiple vendors.#-#(<h1>Install concrete5</h1>|<title>(Group-Office|EspoCRM|nopCommerce) Installation|PrestaShop (Installation Assistant|Wizard Installer)|Subrion CMS Web Installer</title>|install SmartStore.NET now?|Nextpost Installation)#-#',
"/install/index.php",  'AChecker, opencart setup sites.#-#<title>(OpenCart - Installation|AChecker Installation|forma.lms installer)</title>#-#',
"/Install/InstallWizard.aspx", 'DotNetNuke CMS installation tool.#-#<title>        Installation</title>#-#',
"/install/make-config.php", 'ProjectSend installation tool.#-#<title>Install &raquo; ProjectSend</title>#-#',
"/install/system-compatibility", 'Acelle Mail Installer.#-#<title>Requirement - Acelle Installation</title>#-#',
"/installation/default.asp", 'vp-asp shopping cart setup page.#-#<title>Installation Wizard</title>#-#',
"/installation/index.php", 'Joomla Web installer#-#<title>((Joomla! Web|JoomlaPack|Akeeba Backup|Mambo - Web) Installer)</title>#-#',
"/home/index.php", 'XPress Engine CMS Installer.#-#<title>XE Installation</title>#-#',
"/module.php/core/frontpage_welcome.php", 'simpleSAMLphp Installer.#-#<title>simpleSAMLphp installation page</title>#-#',
"/nuxeo/", 'Nuxeo Platform installer.#-#<title>Nuxeo Platform Installation wizard</title>#-#',
"/recovery/install/", 'shopware installer.#-#<title>Shopware .* - Installer</title>#-#',
"/setup/index.php", 'CubeCart / phpMyAdmin installer.#-#<title>(CubeCart .* Installer|phpMyAdmin setup)</title>#-#',
"/setup/install.php", 'osTicket installer.#-#<title>osTicket Installer</title>#-#',
"/setup/setup.php", 'WaWision WaWi, ERP CRM installer.#-#<title>WaWision Installer</title>#-#',
"/tao/install/", 'TAO Installer.#-#<title>TAO Installation</title>#-#'
);

magentofiles = make_array(
"/downloader/", 'Magento Installer.#-#<title>Magento Installation Wizard</title>#-#'
);

wordpressfiles = make_array(
"/wp-admin/install.php", 'Wordpress Installer.#-#<title>WordPress &rsaquo; Installation</title>#-#',
"/wp-admin/setup-config.php", 'Wordpress installer.#-#<title>WordPress &rsaquo; Setup Configuration File</title>#-#'
);

global_var report, VULN;

function check_files( filesarray, dirlist, port ) {

  local_var filesarray, dirlist, port, dir, file, infos, extra, url;

  foreach dir( dirlist ) {

    if( dir == "/" ) dir = "";

    foreach file( keys( filesarray ) ) {

      # infos[0] contains the description, infos[1]  the regex. Optionally infos[2] contains an extra_check for http_vuln_check
      infos = split( filesarray[file], sep:"#-#", keep:FALSE );
      if( max_index( infos ) < 2 ) continue; # Something is wrong with the provided info...

      if( max_index( infos ) > 2 )
        extra = make_list( infos[2] );
      else
        extra = NULL;

      url = dir + file;

      if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:infos[1], extra_check:extra, usecache:TRUE ) ) {
        report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE ) + ":" + infos[0];
        VULN = TRUE;
      }
    }
  }
}

report = 'The following Web App installers are unprotected and publicly accessible  (URL:Description): \n';

port = get_http_port( default:80 );

dirlist = make_list_unique( "/", cgi_dirs( port:port ) );
check_files( filesarray:genericfiles, dirlist:dirlist, port:port );

madirs = get_app_location( port:port, cpe:"cpe:/a:magentocommerce:magento", nofork:TRUE );
if( madirs )
  magentodirlist = make_list_unique( madirs, dirlist );
else
  magentodirlist = dirlist;
check_files( filesarray:magentofiles, dirlist:magentodirlist, port:port );

wpdirs = get_app_location( port:port, cpe:"cpe:/a:wordpress:wordpress", nofork:TRUE );
if( wpdirs )
  wordpressdirlist = make_list_unique( wpdirs, dirlist );
else
  wordpressdirlist = dirlist;
check_files( filesarray:wordpressfiles, dirlist:wordpressdirlist, port:port );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
