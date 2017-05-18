###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_rokbok_plugin_mult_vuln.nasl 5963 2017-04-18 09:02:14Z teissa $
#
# WordPress Rokbox Plugin Multiple Vulnerabilities
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  to gain sensitive information like installation path location.
  Impact Level: Application";
tag_affected = "WordPress Rokbox Plugin versions using TimThumb 1.16 and JW Player 4.4.198";
tag_insight = "Flaws are due to an improper validation of user supplied inputs to the
  'src' parameter in 'thumb.php' and 'aboutlink', 'file' and 'config'
  parameters in 'jwplayer.swf'.";
tag_solution = "Upgrade to the WordPress Rokbox Plugin version 2.1.3,
  For updates refer to http://www.rockettheme.com/wordpress-downloads/plugins/free/2625-rokbox";
tag_summary = "This host is installed with WordPress Rokbox Plugin and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803079";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5963 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-12-18 14:38:17 +0530 (Tue, 18 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Rokbox Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/6006/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118884/wprokbox-shellspoofdosxss.txt");

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
url = dir + '/wp-content/plugins/wp_rokbox/thumb.php?src=' +
            '<body onload=alert(document.cookie)>.jpg';

if(http_vuln_check(port:wpPort, url:url, check_header:TRUE,
       pattern:"alert\(document.cookie\)",
       extra_check:"imThumb version"))
{
  security_message(port:wpPort);
  exit(0);
}
