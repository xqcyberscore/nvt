###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_mult_vuln_oct09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenOffice.org Multiple Vulnerabilities - Oct09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Attackers can exploit these issues to execute code within the
context of the affected application and can deny the service.

Impact Level: Application";

tag_affected = "OpenOffice.org version 3.1.1 and prior on Windows.";

tag_insight = "OpenOffice is prone to multiple unspecified remote security
vulnerabilities, including a stack-based overflow issue and two other
unspecified issues.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host has OpenOffice.org installed and is prone to multiple
vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801114");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3569", "CVE-2009-3570", "CVE-2009-3571");
  script_bugtraq_id(36285);
  script_name("OpenOffice.org Multiple Vulnerabilities - Oct09 (Windows)");
  script_xref(name : "URL" , value : "http://intevydis.com/vd-list.shtml");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Sep/1022832.html");

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer){
  exit(0);
}

# Check for OpenOffice version 3.1.1 => (3.1.9420)
if(version_is_less_equal(version:openVer, test_version:"3.1.9420")){
  security_message(0);
}
