###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_prdts_int_overflow_vuln.nasl 10140 2018-06-08 12:58:24Z asteins $
#
# Foxit Products ICC Parsing Integer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801752");
  script_version("$Revision: 10140 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 14:58:24 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-0332");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Foxit Products ICC Parsing Integer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43329");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0508");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl", "gb_foxit_phantom_detect.nasl");
  script_mandatory_keys("Foxit/Phantom_or_Reader/Installed");
  script_tag(name : "impact" , value : "Successful exploitation could allow attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a
  malicious file.
  Impact Level: System/Application");
  script_tag(name : "affected" , value : "Foxit Reader version prior to 4.3.1.0218
  Foxit Phantom version prior to 2.3.3.1112");
  script_tag(name : "insight" , value : "The flaw is due to an integer overflow error when parsing certain ICC
  chunks and can be exploited to cause a heap-based buffer overflow via a
  specially crafted file.");
  script_tag(name : "solution" , value : "Upgrade to the Foxit Reader version 4.3.1.0218 or later.
  Upgrade to the Foxit Phantom version 2.3.3.1112 or later.
  For updates refer to http://www.foxitsoftware.com/downloads/index.php");
  script_tag(name : "solution_type" , value : "VendorFix");
  script_tag(name : "summary" , value : "The host is installed with Foxit Products and is prone to integer
  overflow vulnerability.");
  exit(0);
}


include("version_func.inc");

foxitVer = get_kb_item("Foxit/Reader/Ver");
if(foxitVer)
{
  if(version_is_less(version:foxitVer, test_version:"4.3.1.0218"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

foxVer = get_kb_item("Foxit/Phantom/Ver");
if(!foxVer){
  exit(0);
}

if(version_is_less(version:foxVer, test_version:"2.3.3.1112")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
