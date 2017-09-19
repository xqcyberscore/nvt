###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_jxr_bof_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# XnView JXR File Handling Buffer Overflow Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804349";
CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2013-3938");
  script_bugtraq_id(66187);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2014-03-26 13:19:16 +0530 (Wed, 26 Mar 2014)");
  script_name("XnView JXR File Handling Buffer Overflow Vulnerability");

  tag_summary =
"This host is installed with XnView and is prone to buffer overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists due to improper validation of 'NUM_ELEMENTS' field in IFD_ENTRY
structures when parsing JXR files.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service or potentially execute arbitrary code on the target machine by
enticing the user of XnView to open a specially crafted file.

Impact Level: System/Application";

  tag_affected =
"XnView version 2.13";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56172");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
version = "";

## Get the version
if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check the vulnerable version
if(version_is_equal(version:version, test_version:"2.13"))
{
  security_message(0);
  exit(0);
}
