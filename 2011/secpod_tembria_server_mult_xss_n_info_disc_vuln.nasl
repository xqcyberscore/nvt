###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tembria_server_mult_xss_n_info_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Tembria Server Multiple Cross-Site Scripting and Information Disclosure Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to gain the sensitive
  information about the user, session, and application and using XSS, an
  attacker could insert malicious code into a web page and entice users to
  execute the  malicious code.
  Impact Level: Application";
tag_affected = "Tembria Server Monitor Version 6.0.4 Build 2229 and prior.";
tag_insight = "Multiple flaws are due to,
  - An error in the Web application management interface, which allows for
    execution of Cross-site Scripting (XSS) attacks.
  - An error in Tembria Server Monitor application allowing an attacker to
    easily decrypt usernames and passwords used to authenticate to the
    application.";
tag_solution = "Upgrade Tembria Server Monitor version 6.0.5 Build 2252 or later,
  For updates refer tohttp://www.tembria.com/download";
tag_summary = "The host is running Tembria Server Monitor and is prone to
  cross-site scripting and information disclosure vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902479");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3684", "CVE-2011-3685");
  script_bugtraq_id(46384);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Tembria Server Multiple Cross-Site Scripting and Information Disclosure Vulnerabilities");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Feb/176");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/Tembria-Server-Monitor-XSS.html");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/Tembria-Server-Monitor-Weak-Xpto-Pwd-Storage.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_tembria_server_monitor_detect.nasl");
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

## Get Tembria Server Monitor Port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Get version from KB
tembriaVer = get_version_from_kb(port:port, app:"tembria");
if(tembriaVer)
{
   ## Check for version before 6.0.5.2252
   if(version_is_less(version:tembriaVer, test_version:"6.0.5.2252")){
     security_message(port);
   }
}
