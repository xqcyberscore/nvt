###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_reader_freetype_engine_int_overflow_vuln.nasl 10140 2018-06-08 12:58:24Z asteins $
#
# Foxit Reader Freetype Engine Integer Overflow Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902605");
  script_version("$Revision: 10140 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 14:58:24 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-1908");
  script_bugtraq_id(48359);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Foxit Reader Freetype Engine Integer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68145");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/msvr11-005.mspx");
  script_xref(name : "URL" , value : "http://www.foxitsoftware.com/products/reader/security_bulletins.php#freetype");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_require_keys("Foxit/Reader/Ver");
  script_tag(name : "impact" , value : "Successful exploitation will let attacker execute arbitrary code or crash an
  affected application or gain the same user rights as the logged-on user.
  Impact Level: System/Application");
  script_tag(name : "affected" , value : "Foxit Reader version prior to 4.0.0.0619");
  script_tag(name : "insight" , value : "The flaw is due to an error in FreeType engine when handling certain
  invalid font type, which allows attackers to execute arbitrary code.");
  script_tag(name : "solution" , value : "Upgrade to Foxit Reader version 4.0.0.0619 or later.
  For updates refer to http://www.foxitsoftware.com/downloads/");
  script_tag(name : "solution_type" , value : "VendorFix");
  script_tag(name : "summary" , value : "The host is installed with Foxit Reader and is prone to
  integer overflow vulnerability.");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

foxVer = get_kb_item("Foxit/Reader/Ver");
if(!foxVer){
  exit(0);
}

## To check Foxit Reader version before 4.0.0.0619
if(version_is_less(version:foxVer,test_version:"4.0.0.0619")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
