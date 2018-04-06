###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_stardict_info_disc_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# StarDict Information Disclosure Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to gain sensitive
information by sniffing the network.

Impact Level: Application";

tag_affected = "StarDict version 3.0.1 on Linux";

tag_insight = "Error exists when 'enable net dict' is configured, and it
attempts to grab clipboard and sends it over network.";

tag_solution = "Upgrade to StarDict 3.0.1-5 or later,
For updates refer to http://www.stardict.org/download.php ";

tag_summary = "This host is installed with StarDict and is prone to
Information Disclosure Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800644");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2260");
  script_name("StarDict Information Disclosure Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/504583");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=508945");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534731");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_stardict_detect_lin.nasl");
  script_require_keys("StarDict/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

stardictVer = get_kb_item("StarDict/Linux/Ver");
if(!stardictVer){
  exit(0);
}

if(stardictVer)
{
  # Check for StarDict version 3.0.1-4.1 (3.0.1)
  if(version_is_equal(version:stardictVer, test_version:"3.0.1")){
    security_message(0);
  }
}
