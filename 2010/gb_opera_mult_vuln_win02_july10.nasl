###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_win02_july10.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# Opera Browser Multiple Vulnerabilities july-10 (Win02)
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

tag_impact = "Successful exploitation will let attackers to cause a denial of service or
  execute arbitrary code.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.54 on Windows.";
tag_insight = "The multiple flaws are cause due to:
  - Fails to restrict certain uses of homograph characters in domain
    names, which makes it easier for remote attackers to spoof IDN domains.
  - Fails to properly restrict access to the full pathname of a file selected
    for upload, which allows attackers to obtain potentially sensitive
    information.
  - Cross site scripting (XSS) vulnerability when handling a data: URI.
  - Fails to properly enforce permission requirements for widget filesystem.";
tag_solution = "Upgrade to Opera 10.54 or later,
  For updates refer to http://www.opera.com/download/?os=windows&list=all";
tag_summary = "The host is installed with Opera web browser and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801370");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2660", "CVE-2010-2661","CVE-2010-2665","CVE-2010-2666");
  script_bugtraq_id(40973);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities july-10 (Win02)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40250");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/962/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1529");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1054/");

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

## Check if version is lesser than 10.54
if(version_is_less(version:operaVer, test_version:"10.54")){
  security_message(0);
}
