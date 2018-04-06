###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_bof_vuln_jul09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer Buffer Overflow Vulnerability - Jul09
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker execute arbitrary
code, corrupt process memory and also crash the bowser leading to
denial-of-service conditions.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 7.x and 8.x";

tag_insight = "The flaw is due to buffer overflow error in the the 'AddFavorite'
method when processing a long URL in the first argument.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Internet Explorer and is prone to
Buffer Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800910");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2433");
  script_bugtraq_id(35620);
  script_name("Microsoft Internet Explorer Buffer Overflow  Vulnerability - Jul09");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9100");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/382393.php");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for IE version 7.0 to 7.00.6000.16441 or 8.0 to 8.0.6001.18702
if(version_in_range(version:ieVer, test_version:"7.0",
                    test_version2:"7.00.6000.16441") ||
   version_in_range(version:ieVer, test_version:"8.0",
                    test_version2:"8.0.6001.18702")){
  security_message(0);
}
