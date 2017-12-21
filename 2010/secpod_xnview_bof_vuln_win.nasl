###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: secpod_xnview_bof_vuln_win.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# XnView DICOM Parsing Integer Overflow Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_summary = "This host has XnView installed and is prone to integer overflow
  vulnerability.

  Vulnerabilities Insight:
  The flaw is due to integer overflow when processing DICOM images with
  certain dimensions. This can be exploited to cause a heap-based buffer
  overflow by persuading a victim to open a specially-crafted DICOM image
  file.";

tag_impact = "Attackers can exploit this issue to cause buffer overflow and execute
  arbitrary code on the system with elevated privileges or cause the
  application to crash.
  Impact Level: System/Application";
tag_affected = "XnView versions prior to 1.97.2 on windows";
tag_solution = "Update to XnView version 1.97.2
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900752");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_bugtraq_id(38629);
  script_cve_id("CVE-2009-4001");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("XnView DICOM Parsing Integer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56802");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509999/100/0/threaded");

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
  ## Check if the version is < 1.97.2
  if(version_is_less(version:xnviewVer, test_version:"1.97.2")){
   security_message(0);
  }
}
