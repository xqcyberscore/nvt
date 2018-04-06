###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_sam_n_opensso_unspecified_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Oracle Java Access Manager and OpenSSO Unspecified Vulnerability
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

tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to affect
  confidentiality and integrity via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Sun OpenSSO Enterprise version 8.0,
  Java System Access Manager version 7.0 and 7.1";
tag_insight = "The flaw is due to unspecified errors in the application, which allows
  remote attackers to affect confidentiality and integrity via unknown
  vectors.";
tag_summary = "The host is running Access Manager or OpenSSO and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902282");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-4444");
  script_bugtraq_id(45884);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Oracle Java Access Manager And OpenSSO Unspecified Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42986");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64811");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0153");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

# Check for Java Access Manager version 7.0 or 7.1
if(amVer[1] =~ "7.0|7.1")
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
