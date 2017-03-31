###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_social_discussions_plugin_mult_vuln.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# WordPress Social Discussions Plugin Multiple Vulnerabilities
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

tag_impact = "Successful exploitation could allow attackers to attackers to
execute arbitrary PHP code and to gain sensitive information like installation
path location.

Impact Level: Application";

tag_affected = "WordPress Social Discussions Plugin version 6.1.1";

tag_insight = "The flaws are due to
- Improper validation of user-supplied input to the 'HTTP_ENV_VARS' parameter
  in 'social-discussions-networkpub_ajax.php'.
- Error in the social-discussions/social-discussions-networkpub.php,
  social-discussions/social-discussions.php and
  social-discussions/social_discussions_service_names.php, which reveals the
  full installation path of the script.";

tag_solution = "Update to version 6.1.2 or later,
For updates refer to http://wordpress.org/extend/plugins/social-discussions";

tag_summary = "This host is running WordPress Social Discussions Plugin and is
prone to remote file inclusion and full path disclosure vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803100";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3058 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-10-18 13:12:20 +0530 (Thu, 18 Oct 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Social Discussions Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.waraxe.us/advisory-93.html");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Oct/98");

  script_summary("Check if WordPress Social Discussions Plugin is prone to path disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
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

## Construct attack
url = dir + "/wp-content/plugins/social-discussions/social-discussions-" +
            "networkpub.php";

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<b>Fatal error</b>:  Call to undefined function " +
             ".*social-discussions-networkpub.php")){
  security_message(port:port);
}
