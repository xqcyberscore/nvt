###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_audacity_bof_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Audacity Buffer Overflow Vulnerability (Windows)
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

tag_impact = "Attacker may leverage this issue by executing arbitrary script code on
  the affected application, and can cause denial of service.
  Impact Level: Application";
tag_affected = "Audacity version prior to 1.3.6 on Windows.";
tag_insight = "Error in the String_parse::get_nonspace_quoted function in
  lib-src/allegro/strparse.cpp file that fails to validate user input data.";
tag_solution = "Upgrade to version 1.3.6 or latest
  http://audacity.sourceforge.net/";
tag_summary = "This host has Audacity installed and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900305");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0490");
  script_bugtraq_id(33090);
  script_name("Audacity Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33356");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7634");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_audacity_detect_win.nasl");
  script_require_keys("Audacity/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

audacityVer = get_kb_item("Audacity/Win/Ver");
if(!audacityVer){
  exit(0);
}

# Check for Audacity version < 1.3.6
if(version_is_less(version:audacityVer, test_version:"1.3.6")){
  security_message(0);
}
