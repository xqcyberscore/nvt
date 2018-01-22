###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_vba_macro_sett_sec_bypass_vuln.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# OpenOffice VBA Macro Restrictions Remote Security Bypass Vulnerability
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation lets the attackers to execute a VBA macro
  bypassing security settings.
  Impact Level: Application";
tag_affected = "OpenOffice.org versions 2.0.4, 2.4.1, and 3.1.1";
tag_insight = "The flaw exists while handling Visual Basic Applications(VBA) macros
  security settings. When a specially crafted document is opened, attacker
  will be able to execute a VBA macro with the ability to bypass macro
  security settings.";
tag_solution = "Upgrade to OpenOffice.org version 3.2 or later,
  http://download.openoffice.org/index.html";
tag_summary = "This host has OpenOffice running which is prone to remote
  security bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800168");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(38245);
  script_cve_id("CVE-2010-0136");
  script_name("OpenOffice VBA Macro Restrictions Remote Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Feb/1023588.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_require_keys("OpenOffice/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get OPenOffice Version from the KB
openOffVer = get_kb_item("OpenOffice/Win/Ver");
if(!openOffVer){
  exit(0);
}

if(openOffVer  =~ "^(2|3)\..*")
{
  ## Check OPenOffice Version 2.0.4, 2.4.1 (2.4.9310) and 3.1.1 (3.1.9420)
  if(version_in_range(version:openOffVer, test_version:"2.0", test_version2:"2.0.4") ||
     version_in_range(version:openOffVer, test_version:"2.4", test_version2:"2.4.9310") ||
     version_in_range(version:openOffVer, test_version:"3.1", test_version2:"3.1.9420")) {
    security_message(0);
  }
}
