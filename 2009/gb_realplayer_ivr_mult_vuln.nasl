###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_ivr_mult_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# RealPlayer IVR Multiple Vulnerabilities
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
  codes within the context of the application and can cause heap overflow
  or cause remote code execution to the application.";
tag_affected = "RealPlayer 11.0.0.477 and prior on all Windows platforms.";
tag_insight = "- Memory corruption while the application processes crafted arbitrary
    'IVR' file.
  - A vulnerability that allows an attacker to write one null byte to an
    arbitrary memory address by using an overly long file name length value.";
tag_solution = "Upgrage to the latest version,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is running RealPlayer which is prone to IVR multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800509");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0375", "CVE-2009-0376");
  script_bugtraq_id(33652);
  script_name("RealPlayer IVR Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/367866.php");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/367867.php");
  script_xref(name : "URL" , value : "http://www.fortiguardcenter.com/advisory/FGA-2009-04.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/500722/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_require_keys("RealPlayer/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(rpVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:rpVer, test_version:"11.0.0.477")){
  security_message(0);
}
