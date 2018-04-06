##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitdefender_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# BitDefender Internet Security 2009 XSS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker execute arbitrary script codes
  in a local context by including a malicious HTML file placed on the local
  system.
  Impact Level: System/Application";
tag_affected = "BitDefender Internet Security version 2009 build 12.0.11.4 and prior.";
tag_insight = "BitDefender Internet Security product fails to properly sanitise the input
  passed through the filename (.rar or .zip archives) of an infected executable
  before being used to output infection details.";
tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one
  For updates refer to http://www.bitdefender.com";
tag_summary = "This host is installed with BitDefender Internet Security and
  is prone to cross site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900327");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0850");
  script_bugtraq_id(33921);
  script_name("BitDefender Internet Security 2009 XSS Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34082");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0557");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/501277/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
  script_dependencies("secpod_bitdefender_prdts_detect.nasl");
  script_require_keys("BitDefender/InetSec/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

bitVer = get_kb_item("BitDefender/InetSec/Ver");
if(!bitVer){
  exit(0);
}

# Check for version 12.0.11.4 and prior
if(version_is_less_equal(version:bitVer, test_version:"12.0.11.4")){
  security_message(0);
}
