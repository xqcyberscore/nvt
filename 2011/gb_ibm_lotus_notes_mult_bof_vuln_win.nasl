###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_mult_bof_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM Lotus Notes File Viewers Multiple BOF Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in the
  context of the user running the application.
  Impact Level: Application";
tag_affected = "IBM Lotus Notes Version 8.5.2 FP2 and prior on windows";
tag_insight = "The flaws are due to:
   - An error within 'xlssr.dll' when parsing a Binary File Format (BIFF)
     record  in an Excel spreadsheet.
   - An integer underflow error within 'lzhsr.dll' when parsing header
     information in a LZH archive file.
   - A boundary error within 'rtfsr.dll' when parsing hyperlink information
     in a Rich Text Format (RTF) document.
   - A boundary error within 'mw8sr.dll' when parsing hyperlink information
     in a Microsoft Office Document (DOC) file.
   - A boundary error within 'assr.dll' when parsing tag information in an
     Applix Spreadsheet.
   - An unspecified error within 'kpprzrdr.dll' when parsing Lotus Notes .prz
     file format.
   - An unspecified error within 'kvarcve.dll' when parsing Lotus Notes .zip
     file format.";
tag_solution = "Upgrade to IBM Lotus Notes 8.5.2 FP3
  For updates refer to http://www.ibm.com/software/lotus/products/notes/";
tag_summary = "This host has IBM Lotus Notes installed and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801945");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-1213", "CVE-2011-1214", "CVE-2011-1215", "CVE-2011-1216",
                "CVE-2011-1217", "CVE-2011-1218", "CVE-2011-1512");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM Lotus Notes File Viewers Multiple BOF Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44624");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67621");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg21500034");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH,");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_require_keys("IBM/LotusNotes/Win/Ver");
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

## Get for IBM Lotus Notes Version
lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer){
 exit(0);
}

## Match main version and ignore the build version
version = eregmatch(pattern:"(([0-9]+\.[0-9]+\.[0-9]+).?([0-9]+)?)", string: lotusVer);
if(version[1] != NULL)
{
  ## Check for IBM Lotus Notes Version < 8.5.2 FP3
  if(version_is_less_equal(version:version[1], test_version:"8.5.2.2")){
    security_message(0);
  }
}
