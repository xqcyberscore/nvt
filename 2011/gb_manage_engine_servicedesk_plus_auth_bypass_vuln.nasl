###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_servicedesk_plus_auth_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ManageEngine ServiceDesk Plus Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to get user names
and passwords of registered users. This may allow an attacker to steal
cookie-based  authentications and launch further attacks.

Impact Level: Application";

tag_affected = "ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.";

tag_insight = "The flaw is due to an error in authentication process, User
passwords are pseudo encrypted and locally stored in user cookies. Having
Javascript code encrypt and decrypt passwords in Login.js file.";

tag_solution = "Vendor has released a patch to fix this issue, please refer
below link for more information.
http://www.manageengine.com/products/service-desk/readme-8.0.html";

tag_summary = "This host is running ManageEngine ServiceDesk Plus and is prone
to authentication bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801984");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-1509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ManageEngine ServiceDesk Plus Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105123/CORE-2011-0506.txt");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/multiples-vulnerabilities-manageengine-sdp");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!get_port_state(port)) {
  exit(0);
}

## Get ManageEngine ServiceDesk Plus Installed version
if(!vers = get_version_from_kb(port:port,app:"ManageEngine")){
  exit(0);
}

## Check the build version
if(' Build ' >< vers){
  vers = ereg_replace(pattern:" Build ", string:vers, replace:".");
}

if(version_is_less_equal(version:vers, test_version:"8.0.0.8013")){
  security_message(port:port);
}
