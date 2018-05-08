###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xnview_mbm_bof_vuln_win.nasl 9744 2018-05-07 11:41:23Z cfischer $
#
# XnView 'MBM' Processing Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  The flaw is due to improper bounds checking when processing 'MBM' (MultiBitMap)
  files, which could be exploited to cause a heap overflow.";

tag_impact = "Successful exploitation will allow attackers to overflow a buffer and execute
  arbitrary code on the system with elevated privileges or cause the application
  to crash.
  Impact Level: System/Application";
tag_affected = "XnView versions prior to 1.97.5 on windows";
tag_solution = "Update to XnView version 1.97.5
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902075");
  script_version("$Revision: 9744 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-07 13:41:23 +0200 (Mon, 07 May 2018) $");
  script_tag(name:"creation_date", value:"2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-1932");
  script_bugtraq_id(40852);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("XnView 'MBM' Processing Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59421");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1468");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jun/1024100.html");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/XnView-MBM-Processing-Heap-Overflow");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

## Get XnView from KB
xnviewVer = get_kb_item("XnView/Win/Ver");
if(xnviewVer != NULL)
{
  ## Check for XnView version less than 1.97.5
  if(version_is_less(version:xnviewVer, test_version:"1.97.5")){
   security_message(0);
  }
}
