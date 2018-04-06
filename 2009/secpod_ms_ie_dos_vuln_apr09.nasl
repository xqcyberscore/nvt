###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_dos_vuln_apr09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer Denial of Service Vulnerability - Apr09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker craft the non-printable
  characters inside a web page and can trick the user to visit the crafted
  web page which will freeze the browser by making the application inactive.
  Impact Level: Application";
tag_affected = "Microsoft Internet Explorer version 7.x and 8.x";
tag_insight = "This flaw might be due to displaying the unprintable characters in Win XP or
  Vista inside Internet Explorer Browser.";
tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one
  For updates refer to http://www.microsoft.com/windows/downloads/ie/getitnow.mspx";
tag_summary = "This host is installed with Internet Explorer and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900337");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1335");
  script_name("Microsoft Internet Explorer Denial of Service Vulnerability - Apr09");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502617/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for Internet Explorer version 7.0 to 7.0.6000.21020 or 8.0 to 8.0.6001.18702
if(version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6000.21020") ||
   version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702")){
  security_message(0);
}
