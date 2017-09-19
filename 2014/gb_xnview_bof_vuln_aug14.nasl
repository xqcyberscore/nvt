###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_bof_vuln_aug14.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# XnView JPEG-LS Image Processing Buffer Overflow Vulnerability
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

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804822");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2012-4988");
  script_bugtraq_id(55787);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2014-08-26 10:14:25 +0530 (Tue, 26 Aug 2014)");
  script_name("XnView JPEG-LS Image Processing Buffer Overflow Vulnerability");

  tag_summary =
"This host is installed with XnView and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists due to improper bounds checking when processing JPEG-LS
(lossless compression) images.";

  tag_impact =
"Successful exploitation will allow remote attackers to potentially execute
arbitrary code on the target machine.

Impact Level: System/Application";

  tag_affected =
"XnView versions 1.99 and 1.99.1";

  tag_solution =
"Update to XnView version 1.99.6 or later. For updates refer to
http://www.xnview.com/en";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/50825");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027607");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79030");
  script_xref(name : "URL" , value : "http://www.reactionpenetrationtesting.co.uk/xnview-jls-heap.html");
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
if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the vulnerable version
if(version_is_equal(version:version, test_version:"1.99") ||
   version_is_equal(version:version, test_version:"1.99.1"))
{
  security_message(0);
  exit(0);
}
