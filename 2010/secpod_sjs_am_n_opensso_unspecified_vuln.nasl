###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sjs_am_n_opensso_unspecified_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Sun JS Access Manager And OpenSSO Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_solution = "Apply the security updates.
  http://sunsolve.sun.com/search/document.do?assetkey=1-66-267568-1

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to affect confidentiality
  and integrity via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Sun OpenSSO Enterprise version 8.0,
  Java System Access Manager version 7.1 and 7.0.2005Q4";
tag_insight = "The flaw is due to unspecified errors in the application, allows remote
  attackers to affect confidentiality and integrity via unknown vectors.";
tag_summary = "The host is running Access Manager or OpenSSO and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902165");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-0894");
  script_bugtraq_id(39457);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Sun JS Access Manager And OpenSSO Unspecified Vulnerability");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57750");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA10-103B.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_sun_opensso_detect.nasl",
                      "secpod_sjs_access_manager_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");

am_port = get_http_port(default:8080);
if(!am_port){
  am_port= 8080;
}

amVer = get_kb_item("www/" + am_port + "/Sun/JavaSysAccessMang");
amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);

# Check for Java Access Manager version 7.0 2005Q4 or 7.1 
if(amVer[1] =~ "7.1|7.0.2005Q4")
{
  security_message(am_port);
  exit(0);
}

ssoVer = get_kb_item("www/" + am_port + "/Sun/OpenSSO");
ssoVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ssoVer);

# Check for Sun OpenSSO version 8.0
if(ssoVer[1] =~ "8.0"){
  security_message(am_port);
}
