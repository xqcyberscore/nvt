###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_win_jul11.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Opera Browser Multiple Vulnerabilities July-11 (Windows)
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Opera Web Browser Version prior 11.50";
tag_insight = "For information about vulnerability refer the references.";
tag_solution = "Upgrade to Opera Web Browser Version 11.50 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802107);
  script_version("$Revision: 5351 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-1337", "CVE-2011-2609", "CVE-2011-2610",
                "CVE-2011-2611", "CVE-2011-2612", "CVE-2011-2613",
                "CVE-2011-2614", "CVE-2011-2615", "CVE-2011-2616",
                "CVE-2011-2617", "CVE-2011-2618", "CVE-2011-2619",
                "CVE-2011-2620", "CVE-2011-2621", "CVE-2011-2622",
                "CVE-2011-2623", "CVE-2011-2624", "CVE-2011-2625",
                "CVE-2011-2626", "CVE-2011-2627");
  script_bugtraq_id(48501, 48500);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities Jul-11 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45060");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68323");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1150/");

  script_tag(name:"qod_type", value:"registry");
  script_summary("Check for the version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Get Opera Version from KB
operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  ## Grep for Opera Versions prior to 11.50
  if(version_is_less(version:operaVer, test_version:"11.50")){
    security_message(0);
  }
}
