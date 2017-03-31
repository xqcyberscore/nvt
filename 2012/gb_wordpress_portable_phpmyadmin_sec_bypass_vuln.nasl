###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_portable_phpmyadmin_sec_bypass_vuln.nasl 3566 2016-06-21 07:31:36Z benallard $
#
# WordPress Portable phpMyAdmin Plugin 'wp-pma-mod' Security Bypass Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information.
  Impact Level: Application";
tag_affected = "WordPress Portable phpMyAdmin plugin version 1.3.0";
tag_insight = "The plugin fails to verify an existing WordPress session when accessing the
  plugin file path directly. An attacker can get a full phpMyAdmin console
  with the privilege level of the MySQL configuration of WordPress by
  accessing 'wp-content/plugins/portable-phpmyadmin/wp-pma-mod'.";
tag_solution = "Upgrade to the WordPress Portable phpMyAdmin Plugin 1.3.1 or later,
  For updates refer to http://wordpress.org/extend/plugins/portable-phpmyadmin/";
tag_summary = "This host is installed with WordPress Portable phpMyAdmin Plugin and is
  prone to security bypass vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803077";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3566 $");
  script_cve_id("CVE-2012-5469");
  script_bugtraq_id(56920);
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:31:36 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-12-17 17:58:04 +0530 (Mon, 17 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Portable phpMyAdmin Plugin 'wp-pma-mod' Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51520/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80654");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Dec/91");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23356/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118805/WordPress-portable-phpMyAdmin-1.3.0-Authentication-Bypass.html");

  script_summary("Check if WP Portable phpMyAdmin Plugin is vulnerable to Security Bypass");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
wpPort = 0;
url = "";
dir = "";

## Get HTTP Port
if(!wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:wpPort)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);

## Construct attack request
url = dir + '/wp-content/plugins/portable-phpmyadmin/wp-pma-mod/';

## Confirm exploit worked properly or not
if(http_vuln_check(port:wpPort, url:url, check_header:TRUE,
                   pattern:"<title>phpMyAdmin",
                   extra_check: make_list('db_structure.php',
                   'server', 'pma_absolute_uri')))
{
  security_message(port:wpPort);
  exit(0);
}
