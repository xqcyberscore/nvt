###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_sql_injection_vuln.nasl 2014-02-10 14:01:01Z feb$
#
# Joomla SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804310";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2780 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-02-10 21:04:07 +0530 (Mon, 10 Feb 2014)");
  script_name("Joomla SQL Injection Vulnerability");

  tag_summary =
"The host is running Joomla and is prone to SQL injection vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is possible to execute sql query.";

  tag_insight =
"The flaw is due to an improper validation of 'id' parameter passed to
'index.php' script.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable
web application.

Impact Level: Application";

  tag_affected =
"Joomla version 3.2.1 and probably other versions.";

  tag_solution =
"Upgrade to version 3.2.3 or later,
For updates refer to http://www.joomla.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/31459/");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomla-321-sql-injection");
  script_summary("Check if Joomla is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
jmPort = "";
req = "";
res = "";
url = "";

## Get Joomla Port
if(!jmPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:jmPort)){
  exit(0);
}

## Construct the Attack Request
url = dir + '/index.php/weblinks-categories?id=/';

## Try attack and check the error to confirm vulnerability.
if(http_vuln_check(port:jmPort, url:url, pattern:"report the error below",
   extra_check:make_list("tag_id", "SQL=SELECT")))
{
  security_message(jmPort);
  exit(0);
}
