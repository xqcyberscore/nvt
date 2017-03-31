###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_prdts_int_overflow_vuln.nasl 3117 2016-04-19 10:19:37Z benallard $
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

tag_impact = "Successful exploitation could allow attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a
  malicious file.
  Impact Level: System/Application";
tag_affected = "Foxit Reader version prior to 4.3.1.0218
  Foxit Phantom version prior to 2.3.3.1112";
tag_insight = "The flaw is due to an integer overflow error when parsing certain ICC
  chunks and can be exploited to cause a heap-based buffer overflow via a
  specially crafted file.";
tag_solution = "Upgrade to the Foxit Reader version 4.3.1.0218 or later.
  Upgrade to the Foxit Phantom version 2.3.3.1112 or later.
  For updates refer to http://www.foxitsoftware.com/downloads/index.php";
tag_summary = "The host is installed with Foxit Products and is prone to integer
  overflow vulnerability.";

if(description)
{
  script_id(801752);
  script_version("$Revision: 3117 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-0332");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Foxit Products ICC Parsing Integer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43329");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0508");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Foxit Reader and Phantom");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect.nasl",
                      "gb_foxit_phantom_detect.nasl");
  script_require_keys("Foxit/Reader/Ver", "Foxit/Phantom/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get the version Foxit Reader from KB
foxitVer = get_kb_item("Foxit/Reader/Ver");
if(foxitVer)
{
  ## Check for Foxit Reader Version less than 4.3.1.0218
  if(version_is_less(version:foxitVer, test_version:"4.3.1.0218"))
  {
    security_message(0);
    exit(0);
  }
}

## Get the Foxit Phantom version from KB
foxVer = get_kb_item("Foxit/Phantom/Ver");
if(!foxVer){
 exit(0);
}

## Check for Foxit Phantom version less than 2.3.3.1112
if(version_is_less(version:foxVer, test_version:"2.3.3.1112")){
       security_message(0);
}
