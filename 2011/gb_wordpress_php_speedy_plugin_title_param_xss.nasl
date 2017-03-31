###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_php_speedy_plugin_title_param_xss.nasl 3570 2016-06-21 07:49:45Z benallard $
#
# WordPress PHP Speedy Plugin 'title' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site.

Impact Level: Application";

tag_affected = "Wordpress PHP Speedy plugin version 0.5.2 and prior.";

tag_insight = "The flaw is caused by an input validation error in the 'title'
parameter in 'wp-content/plugins/php_speedy_wp/libs/php_speedy/view/admin_container.php'
when processing user-supplied data, which could be exploited by attackers to
cause arbitrary scripting code to be executed by the user's browser in the
security context of an affected site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with WordPress PHP Speedy Plugin and is
prone to cross-site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802009";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3570 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:49:45 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress PHP Speedy Plugin 'title' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43652/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if WordPress PHP Speedy Plugin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Path of Vulnerable Page
url = dir + "/wp-content/plugins/php_speedy_wp/libs/php_speedy/view/" +
            "admin_container.php?title=</title><script>alert(11111)</script>";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"</title><script>alert" +
                                   "\(11111\)</script>", check_header:TRUE)){
  security_message(port);
}
