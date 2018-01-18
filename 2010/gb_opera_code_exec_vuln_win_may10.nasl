###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_code_exec_vuln_win_may10.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Opera Browser 'document.write()' Code execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to corrupt memory and execute
  arbitrary code by tricking a user into visiting a specially crafted web page.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.53 on Windows.";
tag_insight = "The flaw is due to an error when continuously modifying document content
  on a web page using 'document.write()' function.";
tag_solution = "Upgrade to the opera version 10.53 or later,
  For updates refer to http://www.opera.com/download/?os=windows&list=all";
tag_summary = "The host is installed with Opera web browser and is prone to
  arbitrary code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801331");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser 'document.write()' Code execution Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39590");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58231");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/953/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0999");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1053/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get Opera version from from KB list
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check if version is lesser than 10.53
if(version_is_less(version:operaVer, test_version:"10.53")){
  security_message(0);
}
