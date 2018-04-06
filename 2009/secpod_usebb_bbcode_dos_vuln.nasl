###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_usebb_bbcode_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# UseBB BBcode Parsing Remote Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code and cause Denial-of-Service by posting a message containing specially
  crafted BBcode.
  Impact Level: Applicatioin.";
tag_affected = "UseBB version 1.0.9 and prior on all platforms.";
tag_insight = "This issue is due to an infinite loops while parsing for malformed
  BBcode.";
tag_solution = "Upgrade to UseBB version 1.0.10
  For updates refer to http://www.usebb.net/downloads/";
tag_summary = "This host has UseBB installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901057");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4041");
  script_bugtraq_id(37010);
  script_name("UseBB BBcode Parsing Remote Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37328");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3222");
  script_xref(name : "URL" , value : "http://www.usebb.net/community/topic-post9775.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_usebb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

usebbPort = get_http_port(default:80);
if(!usebbPort){
  exit(0);
}

usebbVer = get_kb_item("www/"+ usebbPort + "/UseBB");
if(!usebbVer){
  exit(0);
}

usebbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:usebbVer);
if(usebbVer[1])
{
  # Check for UseBB version prior to 1.0.10
  if(version_is_less(version:usebbVer[1], test_version:"1.0.10")){
    security_message(usebbPort);
  }
}
