###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_iloveit_theme_mult_vuln.nasl 2935 2016-03-24 08:28:18Z benallard $
#
# Wordpress I Love It Theme Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803844";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2935 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:28:18 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-07-29 12:46:47 +0530 (Mon, 29 Jul 2013)");
  script_name("Wordpress I Love It Theme Multiple Vulnerabilities");

  tag_summary =
"This host is installed with Wordpress I Love It Theme and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Send a HTTP GET request and check whether it is able to disclose the path
or not.";

  tag_insight =
"Multiple flaws are due to,
- Input passed via 'playerID' parameter to '/iloveit/lib/php/assets/player.swf'
  script is not properly sanitised before being return to the user.
- Not properly restrict access to certain files.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code in the context of the affected site and disclose some sensitive
information.

Impact Level: Application";

  tag_affected =
"Wordpress I Love It Theme version 1.9 and prior";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013070104");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122386/wpiloveit-xssdisclose.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-i-love-it-xss-content-spoofing-path-disclosure");
  script_summary("Check if Wordpress I Love It Theme is prone to path disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct the Attack Request
url = dir + "/wp-content/themes/iloveit/index.php";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
        pattern:"<b>Fatal error</b>: .*index.php"))
{
  security_message(port);
  exit(0);
}
