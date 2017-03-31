###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_foxypress_mult_vuln.nasl 3566 2016-06-21 07:31:36Z benallard $
#
# WordPress FoxyPress Plugin Multiple Vulnerabilities
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary web script or HTML in a user's browser session in the context of an
affected site, manipulate SQL queries by injecting arbitrary SQL code and to
redirect users to arbitrary web sites and conduct phishing attacks.

Impact Level: Application";

tag_affected = "WordPress FoxyPress Plugin Version 0.4.2.5 and prior";

tag_insight = "Inputs passed via the
- 'xtStartDate', 'txtEndDate', and 'txtProductCod' parameters to edit.php,
- 'id' parameter to foxypress-manage-emails.php,
- 'status' and 'page' parameters to edit.php and
- 'url' parameter to foxypress-affiliate.php are not properly sanitised
before being returned to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running WordPress FoxyPress plugin and is prone to
multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803042";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3566 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:31:36 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-11-02 18:49:49 +0530 (Fri, 02 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress FoxyPress Plugin Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.waraxe.us/content-95.html");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51109/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22374/");

  script_summary("Check if WordPress FoxyPress Plugin is vulnerable to URL redirection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
port = "";
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack
url = string(dir, "/wp-content/plugins/foxypress/foxypress-affiliate.php?url=" +
             "http://", get_host_name(), dir, "//index.php");

## Confirm exploit worked properly or not
sndReq = http_get(item:url, port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Check the response to confirm vulnerability
if(rcvRes &&  rcvRes =~ "HTTP/1.. 302 Found" &&
   egrep(pattern:'^Location:.*/index.php', string:rcvRes)){
  security_message(port);
}
