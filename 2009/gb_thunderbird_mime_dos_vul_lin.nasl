################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_mime_dos_vul_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Thunderbird DoS attacks via malformed MIME emails (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

tag_summary = "The host is running Mozilla Thunderbird which is prone to denial
  of service vulnerability.

  Vulnerability:
  Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822
  headers.";

tag_impact = "Successful exploitation could result in disruption or unavailability
  of service.
  Impact Level: Application.";
tag_affected = "Thunderbird version 2.0.0.14 and prior on Linux.";
tag_solution = "Upgrade to Thunderbird version 3.0.4 or later
  For updates refer to http://www.mozilla.com/en-US/products/thunderbird/";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800502");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5430");
  script_name("Thunderbird DoS attacks via malformed MIME emails (Linux)");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/364761.php");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-68.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Thunderbird/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(!tbVer){
  exit(0);
}

# Thunderbird version <= 2.0.0.14
 if(version_is_less_equal(version:tbVer, test_version:"2.0.0.14")){
   security_message(0);
   }
