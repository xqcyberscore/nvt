###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wpecommerce_plugin_xss_vuln.nasl 3507 2016-06-14 04:32:30Z ckuerste $
#
# WordPress WP e-Commerce Plugin 'cart_messages' Parameter Cross-site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to insert arbitrary
HTML and script code, which will be executed in a user's browser session in the
context of an affected site when the malicious data is being viewed.

Impact Level: Application";

tag_affected = "WordPress WP e-Commerce Plugin version 3.8.6 and prior.";

tag_insight = "The flaw is due to improper validation of user-supplied input
passed via the 'cart_messages[]' parameter to '/wp-content/plugins/wp-e-commerce
/wpsc-theme/wpsc-cart_widget.php', which allows attacker to execute
arbitrary HTML and script code on the user's browser session in the security
context of an affected site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with WordPress WP e-Commerce plugin and
is prone to cross-site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802321";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3507 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 06:32:30 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_bugtraq_id(49009);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress WP e-Commerce Plugin 'cart_messages' Parameter Cross-site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45513/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519149");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_wp_e_commerce.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103724/wpecommerce-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if WordPress WP e-Commerce plugin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
url = dir + "/wp-content/plugins/wp-e-commerce/wpsc-theme/wpsc-cart_widget.php?" +
            "cart_messages[]=<script>alert(document.cookie);</script>";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
                   pattern:"<script>alert\(document.cookie\);</script>", check_header:TRUE)){
  security_message(port);
}
