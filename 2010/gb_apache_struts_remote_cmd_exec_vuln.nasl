##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_remote_cmd_exec_vuln.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# Struts Remote Command Execution Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to manipulate server-side context
  objects with the privileges of the user running the application.
  Impact Level: Application.";
tag_affected = "Struts version 2.0.0 through 2.1.8.1";

tag_insight = "The flaw is due to an error in 'OGNL' extensive expression evaluation
  capability in XWork in Struts, uses as permissive whitelist, which allows
  remote attackers to modify server-side context objects and bypass the '#'
  protection mechanism in ParameterInterceptors via various varibles.";
tag_solution = "Upgrade to Struts version 2.2 or later
  For updates refer to http://struts.apache.org/download.cgi";
tag_summary = "This host is running Struts and is prone to remote command
  execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801441");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-1870");
  script_bugtraq_id(41592);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Struts Remote Command Execution Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14360/");
  script_xref(name : "URL" , value : "http://struts.apache.org/2.2.1/docs/s2-005.html");
  script_xref(name : "URL" , value : "http://blog.o0o.nu/2010/07/cve-2010-1870-struts2xwork-remote.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}
		

include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
stPort = get_http_port(default:8080);
if(!get_port_state(stPort)){
  exit(0);
}

## GET the version from KB
stVer = get_kb_item("www/" + stPort + "/Apache/Struts");
stVer = eregmatch(pattern:"^(.+) under (/.*)$", string:stVer);

## Check for the Struts version
if(stVer[1] != NULL)
{
  if(version_in_range(version:stVer[1], test_version:"2.0", test_version2:"2.1.8.1")){
   security_message(stPort);
  }
}
