###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_power_point_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft PowerPoint 2007 OfficeArt Atom Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
codes, can cause memory corruption and other attacks in the context of the
application through a crafted Power Point file.

Impact Level: System";

tag_affected = "MS PowerPoint 2007 Service Pack 2";

tag_insight = "The flaw exists with the way application will parse external
objects within an Office Art container. When parsing this object, the
application will append an uninitialized object to a list. When destroying this
object during document close (WM_DESTROY), the application will access a method
that does not exist.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Microsoft Office Power Point and is
prone to remote code execution vulnerability.

This NVT has been replaced by NVT secpod_ms11-022.nasl
(OID:1.3.6.1.4.1.25623.1.0.902411).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801594");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0976");
  script_name("Microsoft PowerPoint 2007 OfficeArt Atom Remote Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-044/");
  script_xref(name : "URL" , value : "http://dvlabs.tippingpoint.com/blog/2011/02/07/zdi-disclosure-microsoft");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_ms_office_detection_900025.nasl", "secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-021.nasl.

include("version_func.inc");

## check for microsoft office installation
if(!get_kb_item("MS/Office/Ver") =~ "^12\.*"){
  exit(0);
}

## Get the ms office power point version
ppVer = get_kb_item("SMB/Office/PowerPnt/Version");

## Check for the MS office power point 2007
if(ppVer &&  ppVer =~ "^12\.*"){
  security_message(0);
}
