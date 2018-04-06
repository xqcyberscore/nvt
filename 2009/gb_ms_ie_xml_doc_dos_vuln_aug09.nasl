###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_xml_doc_dos_vuln_aug09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer XML Document DoS Vulnerability - Aug09
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to cause
Denial of Service in the context of an affected application.

Impact Level: Application";

tag_affected = "Internet Explorer version 6.x to 6.0.2900.2180 and 7.x to
7.0.6000.16473";

tag_insight = "The flaw exists via an XML document composed of a long series
of start-tags with no corresponding end-tags and it leads to CPU consumption.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host has Internet Explorer installed and is prone to Denial
of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800863");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2668");
  script_name("Microsoft Internet Explorer XML Document DoS Vulnerability - Aug09");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3216/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2009-07/0193.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/EXE/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

# Get for Internet Explorer Version
ieVer = get_kb_item("MS/IE/EXE/Ver");

if(!isnull(ieVer))
{
  # Check for IE version 6.0 <= 6.0.2900.2180 or 7.0 <= 7.0.6000.16473
  if(version_in_range(version:ieVer, test_version:"6.0",
                                    test_version2:"6.0.2900.2180")||
     version_in_range(version:ieVer, test_version:"7.0",
                                    test_version2:"7.0.6000.16473")){
    security_message(0);
  }
}
