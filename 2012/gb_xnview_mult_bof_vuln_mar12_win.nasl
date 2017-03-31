###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: gb_xnview_mult_bof_vuln_mar12_win.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# XnView Multiple Buffer Overflow Vulnerabilities - Mar12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_summary = "This host has XnView installed and is prone to multiple heap based
  buffer overflow vulnerabilities.

  Vulnerabilities Insight:
  The flaws are due to
  - A signedness error in the FlashPix plugin (Xfpx.dll) when validating
    buffer sizes to process image's content.
  - An error when processing image data within Personal Computer eXchange
    (PCX) files.
  - A boundary error when parsing a directory, which allows attackers to cause a
    buffer overflow when browsing folder from an extracted archive file.";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on the
  system via a specially crafted files or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "XnView versions 1.98.5 and prior on windows";
tag_solution = "Update to XnView version 1.98.8 or later,
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_id(802815);
  script_version("$Revision: 3062 $");
  script_bugtraq_id(52405);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-03-15 12:56:44 +0530 (Thu, 15 Mar 2012)");
  script_name("XnView Multiple Buffer Overflow Vulnerabilities - Mar12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47388/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18491/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52405/info");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5285780.html");

  script_summary("Check for the version of XnView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_require_keys("XnView/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
xnviewVer = NULL;

## Get XnView from KB
xnviewVer = get_kb_item("XnView/Win/Ver");
if(isnull(xnviewVer)){
  exit(0);
}

## Check if the version is < 1.98.8
if(version_is_less(version:xnviewVer, test_version:"1.98.8")){
  security_message(0);
}
