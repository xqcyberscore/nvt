###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_register_plus_redux_mult_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# WordPress Register Plus Redux Plugin Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
################################################################################

tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site or obtain sensitive information.
  Impact Level: Application";
tag_affected = "WordPress Register Plus Redux Plugin 3.7.3.1 and prior.";
tag_insight = "The flaws are due to,
  - Improper validation of input passed to 'wp-login.php' script (when
    'action' is set to 'register').
  - A direct request to 'dashboard_invitation_tracking_widget.php' and
    'register-plus-redux.php' allows remote attackers to obtain installation
    path in error message.";
tag_solution = "Upgrade to WordPress Register Plus Redux Plugin version 3.8 or later,
  For updates refer to http://wordpress.org/extend/plugins/register-plus-redux/";
tag_summary = "The host is running WordPress Register Plus Redux Plugin and is
  prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902656";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7019 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-12-30 15:11:51 +0530 (Fri, 30 Dec 2011)");
  script_name("WordPress Register Plus Redux Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/5532/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45503/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosiure/2011/Dec/489");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108235/registerplus3731-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2011 SecPod");
  script_category(ACT_ATTACK);
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


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:wpPort)){
  exit(0);
}

## Get WordPress Directory
if(!wpDir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);

## Try an exploit
url = wpDir + "/wp-content/plugins/register-plus-redux/register-plus-redux.php";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:wpPort, url:url, pattern:"<b>Fatal error</b>:  Call" +
               " to undefined function.*register-plus-redux.php")){
    security_message(wpPort);
}

