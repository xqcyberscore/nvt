###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_servicedesk_plus_mult_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ManageEngine ServiceDesk Plus Multiple XSS Vulnerabilities
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of a vulnerable
site. This may allow an attacker to steal cookie-based authentications and
launch further attacks.

Impact Level: Application";

tag_affected = "ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.";

tag_insight = "Multiple flaws are due to an error in,
- 'SetUpWizard.do' when handling configuration wizard (add new technician)
  action via 'Name' parameter.
- 'SiteDef.do' when handling add a new site action via 'Site name' parameter.
- 'GroupResourcesDef.do' when handling add a create group action via
  'Group Name' parameter.
- 'LicenseAgreement.do' when handling add a new license agreement action via
  'Agreement Number' parameter.
- 'ManualNodeAddition.do' when handling server configuration (computer)
   action via 'Name' parameter.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running ManageEngine ServiceDesk Plus and is prone
to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801962");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_bugtraq_id(48928);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ManageEngine ServiceDesk Plus Multiple XSS Vulnerabilities");
  script_xref(name : "URL" , value : "http://sebug.net/exploit/20793/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68717");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17586/");

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
  script_tag(name:"solution_type", value:"WillNotFix");
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
