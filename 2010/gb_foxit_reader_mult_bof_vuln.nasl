###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_mult_bof_vuln.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Foxit Reader Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow the attackers to execute arbitrary code
  in the context of an application that uses the affected library. Failed
  exploit attempts will likely result in denial-of-service conditions.
  Impact Level: Application";
tag_affected = "Foxit Reader version prior to 4.1.1 (4.1.1.0805)";
tag_insight = "Multiple flaws are due to an error in the handling of 'PDF'
  documents. It is not properly rendering the PDF documents.";
tag_solution = "Upgrade to the Foxit Reader version 4.1.1 or later,
  For updates refer to http://www.foxitsoftware.com/downloads/index.php";
tag_summary = "The host is installed with Foxit Reader and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801425");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_bugtraq_id(42241);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Foxit Reader Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/42241/");
  script_xref(name : "URL" , value : "http://www.foxitsoftware.com/pdf/reader/security_bulletins.php#iphone");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/current/index.html#foxit_releases_foxit_reader_4");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_require_keys("Foxit/Reader/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get the version from KB
foxitVer = get_kb_item("Foxit/Reader/Ver");
if(!foxitVer){
  exit(0);
}

## Check for Foxit Reader Version less than 4.1.1.0805
if(version_is_less(version:foxitVer, test_version:"4.1.1.0805")){
  security_message(0);
}
