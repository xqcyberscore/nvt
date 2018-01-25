###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_info_disc_vuln_feb10_win.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Opera Information Disclosure Vulnerability - (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
information via a crafted document.

Impact Level: Application";
tag_affected = "Opera version prior to 10.10 on Windows.";
tag_insight = "- Opera permits cross-origin loading of CSS stylesheets even when the
stylesheet download has an incorrect MIME type and the stylesheet document
is malformed.";
tag_solution = "Upgrade to Opera version 10.10.
For updates refer to http://www.opera.com/download/?custom=yes";
tag_summary = "The host is installed with Opera Web Browser and is prone to
Information Disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902122");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0653");
  script_name("Opera Information Disclosure Vulnerability - (Windows)");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/390938.php");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=9877");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

# Check if version is lesser than 10.50b1 => (10.50)
if(version_is_less(version:operaVer, test_version:"10.10")){
  security_message(0);
}
