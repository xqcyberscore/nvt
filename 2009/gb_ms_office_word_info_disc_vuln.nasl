###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_word_info_disc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Word 2007 Sensitive Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation could allow remote attackers to retrieve sensitive
  information about sender's account name and a Temporary Internet Files
  subdirectory name.
  Impact Level: System";
tag_affected = "Microsoft Office Word 2007 on Windows.";
tag_insight = "In MS Word when the Save as PDF add-on is enabled, places an absolute pathname
  in the Subject field during an Email as PDF operation.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://office.microsoft.com/en-us/word/default.aspx";
tag_summary = "This host is installed with Microsoft Word and is prone to
  information disclosure vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800343");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-6063");
  script_name("Microsoft Word 2007 Sensitive Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/486088/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Word/Version");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

if(egrep(pattern:"^12\..*", string:get_kb_item("MS/Office/Ver")))
{
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  # Grep for version 12.0 to 12.0.6331.4999
  if(version_in_range(version:wordVer, test_version:"12.0",
                                       test_version2:"12.0.6331.4999")){
    security_message(0);
  }
}
