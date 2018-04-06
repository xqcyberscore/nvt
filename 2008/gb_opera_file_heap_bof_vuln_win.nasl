###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_file_heap_bof_vuln_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Opera Web Browser Heap Based Buffer Overflow Vulnerability (Windows)
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

tag_impact = "Successful remote attack could allow arbitrary code execution
  by tricking user into opening malicious HTML file.
  Impact Level: Application";
tag_affected = "Opera version 9.62 and prior on Windows.";
tag_insight = "The flaw is due to an error while processing an overly long
  file:// URI.";
tag_solution = "Upgrade to Opera 9.63
  http://www.opera.com/download/";
tag_summary = "The host is installed with Opera Web Browser and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800066");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5178");
  script_bugtraq_id(32323);
  script_name("Opera Web Browser Heap Based Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7135");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/3183");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_mandatory_keys("Opera/Win/Version");
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

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"9.62")){
  security_message(0);
}
