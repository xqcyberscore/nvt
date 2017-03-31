###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_zingiri_tickets_file_disc_vuln.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# WordPress Zingiri Tickets Plugin File Disclosure Vulnerability
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

tag_impact = "Successful exploitation could allow attackers to gain sensitive
information.

Impact Level: Application";

tag_affected = "WordPress Zingiri Tickets Plugin version 2.1.2";

tag_insight = "The flaw is due to insufficient permissions to the 'log.txt',
which reveals administrative username and password hashes via direct http
request.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with WordPress Zingiri Tickets plugin and
is prone to file disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802750";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3058 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-04-18 11:03:03 +0530 (Wed, 18 Apr 2012)");
  script_name("WordPress Zingiri Tickets Plugin File Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111904/wpzingiritickets-disclose.txt");

  script_summary("Check file disclosure vulnerability in WordPress Zingiri Tickets plugin");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Variable Initialization
port = "";
dir = "";
url = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the attack req
url = string(dir, "/wp-content/plugins/zingiri-tickets/log.txt");

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, pattern:"\[group_id\]",
                   extra_check:make_list("\[dept_id\]", "\[passwd\]",
                   "\[email\]"))){
  security_message(port:port);
}
