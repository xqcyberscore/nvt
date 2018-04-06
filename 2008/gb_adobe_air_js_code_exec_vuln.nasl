###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_js_code_exec_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Adobe AIR JavaScript Code Execution Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Remote exploitation could lead to unauthorized disclosure of
  information, modification of files, and disruption of service.
  Impact Level: Application";
tag_affected = "Adobe AIR 1.1 and earlier on Windows.";
tag_insight = "The issue is due to improper sanitization of Javascript in the
  application.";
tag_solution = "Upgrade to Adobe AIR 1.5
  http://get.adobe.com/air";
tag_summary = "This host has Adobe AIR installed, and is prone to privilege
  escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800065");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5108");
  script_bugtraq_id(32334);
  script_name("Adobe AIR JavaScript Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!(get_kb_item("SMB/WindowsVersion"))){
  exit(0);
}

airVer = registry_get_sz(item:"DisplayVersion",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe AIR");
if(airVer)
{
  if(version_is_less(version:airVer, test_version:"1.5.0.7220")){
    security_message(0);
  }
}
