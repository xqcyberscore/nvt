###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_smf_comp_xss_vuln.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Joomla Component SMF Cross Site Scripting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804273";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_bugtraq_id(66945);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-30 14:13:30 +0530 (Wed, 30 Apr 2014)");
  script_name("Joomla Component SMF Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Joomla! component SMF and is prone to cross site
scripting vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is possible to
read a given string.";

  tag_insight =
"The flaw is due to insufficient validation of 'itemid' HTTP GET parameter
passed to 'index.php' script.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary script
code in a user's browser session within the trust relationship between their
browser and the server.

Impact Level: Application";

  tag_affected =
"SMF Component for Joomla";

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

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126176");
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
url = dir + '/index.php?option=com_smf&itemid="><marquee>XSS-TEST</marquee>';

## Check the response to confirm vulnerability, extra check not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:">XSS-TEST<", extra_check:"com_smf"))
{
  security_message(http_port);
  exit(0);
}
