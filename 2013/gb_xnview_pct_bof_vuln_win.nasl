###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_pct_bof_vuln_win.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# XnView PCT File Handling Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: System/Application";

CPE = "cpe:/a:xnview:xnview";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803740";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6079 $");
  script_cve_id("CVE-2013-2577");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
  script_tag(name:"creation_date", value:"2013-08-21 12:23:59 +0530 (Wed, 21 Aug 2013)");
  script_name("XnView PCT File Handling Buffer Overflow Vulnerability");

  tag_summary =
"This host is installed XnView and is prone to buffer overflow Vulnerability.";

  tag_vuldetect =
"Get the installed version of XnView with the help of detect NVT and check
the version is vulnerable or not.";

  tag_insight =
"The flaw is due to an improper bounds checking when processing '.PCT' files.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code on the target machine, by enticing the user of XnView to open a specially
crafted file.";

  tag_affected =
"XnView versions 2.03 and prior for Windows.";

  tag_solution =
"Upgrade to XnView 2.04 or later,
For updates refer to http://www.xnview.com/en/xnview/#downloads";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/85919");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27049");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028817");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/advisories/xnview-buffer-overflow-vulnerability");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2013-07/0153.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Variables Initialization
version = "";

## Get the version
if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check the vulnerable version
if(version_is_less(version:version, test_version:"2.04"))
{
  security_message(0);
  exit(0);
}
