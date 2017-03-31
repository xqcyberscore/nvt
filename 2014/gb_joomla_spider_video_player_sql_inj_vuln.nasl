###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_spider_video_player_sql_inj_vuln.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# Joomla! Spider video player Component SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804760");
  script_version("$Revision: 2780 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-08-27 15:58:01 +0530 (Wed, 27 Aug 2014)");
  script_name("Joomla! Spider video player Component SQL Injection Vulnerability");

  tag_summary =
"This host is installed with Joomla! Spider video player Component and is
prone to sql injection vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to
execute sql query or not.";

  tag_insight =
"Flaw is due to the /component/spidervideoplayer/index.php script not properly
sanitizing user-supplied input to the 'theme' parameter.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code and SQL statements on the vulnerable system, which may leads to
access or modify data in the underlying database.

Impact Level: Application";

  tag_affected =
"Joomla! Spider video player Component version 2.8.3, Other versions may also
be affected.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/128007");
  script_summary("Check if Joomla! Spider video player Component is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + "/component/spidervideoplayer/?view=settings&format=row&"
          + "typeselect=0&playlist=1,&theme='SQL-Injection-Test" ;

## Check the response to confirm vulnerability, extra check not possible
if(http_vuln_check(port:http_port, url:url, check_header:FALSE,
               pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
{
  security_message(http_port);
  exit(0);
}
