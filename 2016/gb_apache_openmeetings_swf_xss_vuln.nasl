###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_openmeetings_swf_xss_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Apache OpenMeetings 'SWF panel' Cross-site Scripting Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:apache:openmeetings";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808658");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-3089");
  script_bugtraq_id(92442);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-08-23 15:09:03 +0530 (Tue, 23 Aug 2016)");
  script_name("Apache OpenMeetings 'SWF panel' Cross-site Scripting Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Apache
  OpenMeetings and is prone to cross site scripting vulnerability.");

  script_tag(name: "vuldetect" , value:"Send a crafted HTTP GET request and
  check whether it is possible to read a cookie or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an improper
  sanitization of input to 'swf'query parameter in swf panel.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within 
  the trust relationship between their browser and the server.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Apache OpenMeetings prior to 3.1.2");

  script_tag(name: "solution" , value:"Upgrade to Apache OpenMeetings version 3.1.2
  For updates refer to http://openmeetings.apache.org/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name : "URL" , value : "http://openmeetings.apache.org/security.html");
  script_xref(name : "URL" , value : "https://www.apache.org/dist/openmeetings/3.1.2/CHANGELOG");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_openmeetings_detect.nasl");
  script_mandatory_keys("Apache/Openmeetings/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
report = "";
openPort = 0;

## Get HTTP Port
if(!openPort = get_app_port(cpe:CPE)){
  exit(0);
}

##Get install location
if(!dir = get_app_location(cpe:CPE, port:openPort)){
  exit(0);
}

##Construct Attack URL
url = dir + '/swf?swf=%3Cscript%3Ealert%28document.cookie%29%3C/script%3E';

##Send Request and check vulnerability
if(http_vuln_check(port:openPort, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>", 
   extra_check:make_list(">OpenMeetings<", ">Timezone<")))
{
  report = report_vuln_url( port:openPort, url:url );
  security_message(port:openPort, data:report);
  exit(0);
}
