###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_code_exec_n_dos_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Shockwave Player Multiple Code Execution and DoS Vulnerabilities (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  to cause a denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Shockwave Player Versions prior to 11.6.5.635 on Mac OS X";
tag_insight = "Multiple flaws are due to
  - An error within the IMLLib, DPLib and IMLLib modules when parsing a '.dir'.
  - An unspecified errors.";
tag_solution = "Upgrade to Adobe Shockwave Player version 11.6.5.635 or later,
  For updates refer to http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host is installed with Adobe Shockwave Player and is prone
  to multiple code execution and denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802780");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(53420);
  script_cve_id("CVE-2012-2029", "CVE-2012-2030", "CVE-2012-2031", "CVE-2012-2032",
                "CVE-2012-2033");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-15 12:12:47 +0530 (Tue, 15 May 2012)");
  script_name("Adobe Shockwave Player Multiple Code Execution and DoS Vulnerabilities (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49086/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-13.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Shockwave/Player/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
shockVer = "";

shockVer = get_kb_item("Adobe/Shockwave/Player/MacOSX/Version");
if(!shockVer){
  exit(0);
}

## Check for Adobe Shockwave Player versions prior to 11.6.3.635
if(version_is_less(version:shockVer, test_version:"11.6.3.635")){
  security_message(0);
}
