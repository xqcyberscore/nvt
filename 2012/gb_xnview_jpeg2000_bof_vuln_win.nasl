###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xnview_jpeg2000_bof_vuln_win.nasl 9744 2018-05-07 11:41:23Z cfischer $
#
# XnView JPEG2000 Plugin Buffer Overflow Vulnerability (Windows)
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

tag_summary = "This host has XnView installed and is prone to buffer overflow
vulnerability.

Vulnerabilities Insight:
The flaw is due to an error in the JPEG2000 plugin in Xjp2.dll, when
processing a JPEG2000 (JP2) file with a crafted Quantization Default (QCD)
marker segment.";

tag_impact = "Successful exploitation will allows attackers to execute arbitrary code in
the context of the affected application or cause a denial of service
condition.

Impact Level: System/Application";

tag_affected = "XnView version 1.98.5 and prior.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802816");
  script_version("$Revision: 9744 $");
  script_cve_id("CVE-2012-1051");
  script_bugtraq_id(51896);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-07 13:41:23 +0200 (Mon, 07 May 2018) $");
  script_tag(name:"creation_date", value:"2012-03-15 16:28:54 +0530 (Thu, 15 Mar 2012)");
  script_name("XnView JPEG2000 Plugin Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47352");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73040");

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
  script_tag(name:"solution_type", value:"WillNotFix");
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

## Check if the version is equal to 1.98.5
if(version_is_less_equal(version:xnviewVer, test_version:"1.98.5")){
  security_message(0);
}
