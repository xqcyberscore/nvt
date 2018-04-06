###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_recursion_dos_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ClamAV Recursion Level Handling Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to cause a denial of service
  (crash) via vectors related to recursion level.
  Impact Level: Application";
tag_affected = "ClamAV before 0.97.3 on Windows.";
tag_insight = "The flaw is due to the way the bytecode engine handled recursion
  level when scanning an unpacked file.";
tag_solution = "Upgrade to ClamAV version 0.97.3 or later
  For updates refer to http://www.clamav.net/lang/en/download/";
tag_summary = "The host is installed with ClamAV and is prone to denial of service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902760");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3627");
  script_bugtraq_id(50183);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-22 17:51:52 +0530 (Tue, 22 Nov 2011)");
  script_name("ClamAV Recursion Level Handling Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.ubuntu.com/usn/USN-1258-1/");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=746984");
  script_xref(name : "URL" , value : "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=3d664817f6ef833a17414a4ecea42004c35cc42f");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_require_keys("ClamAV/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

avVer = get_kb_item("ClamAV/Win/Ver");
if(avVer == NULL){
  exit(0);
}

if(version_is_less(version:avVer, test_version:"0.97.3")){
  security_message(0);
}
