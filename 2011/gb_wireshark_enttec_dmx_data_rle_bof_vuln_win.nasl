###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_enttec_dmx_data_rle_bof_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Wireshark ENTTEC DMX Data RLE Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to create a denial of service
  or execute arbitrary code.
  Impact Level: Application";
tag_affected = "Wireshark version 1.4.2";
tag_insight = "The flaw is caused by a boundary error in the 'dissect_enttec_dmx_data()'
  function when processing RLE Compressed DMX data of the ENTTEC protocol
  which can be exploited to cause a buffer overflow via a specially crafted
  packet.";
tag_solution = "Upgrade to the latest version of Wireshark 1.4.3,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801828");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4538");
  script_bugtraq_id(45634);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Wireshark ENTTEC DMX Data RLE Buffer Overflow Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42767");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0079");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5539");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
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

## Confirm Windows
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check Wireshark version 1.4.2
if(version_is_equal(version:sharkVer, test_version:"1.4.2")){
  security_message(0);
}
