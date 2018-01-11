###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_static_html_xss_vuln.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Microsoft Internet Explorer 'toStaticHTML()' Cross Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to bypass the
cross-site scripting (XSS) protection mechanism and conduct XSS attacks.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 8.x to 8.0.6001.18702";

tag_insight = "The flaw is due to error in the 'toStaticHTML()' which is not
properly handling the 'Cascading Style Sheets (CSS)'.";

tag_solution = "Run Windows Update and update the listed hotfixes or download
and update mentioned hotfixes in the advisory from the below link,
http://www.microsoft.com/technet/security/Bulletin/MS10-071.mspx";

tag_summary = "This host is installed with Internet Explorer and is prone to
cross site scripting vulnerability.

This NVT has been replaced by NVT secpod_ms10-071.nasl
(OID:1.3.6.1.4.1.25623.1.0.901162).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902246");
  script_version("$Revision: 8356 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-3324");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft Internet Explorer 'toStaticHTML()' Cross Site Scripting Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.wooyun.org/bug.php?action=view&id=189");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2010-08/0179.html");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-071.nasl.

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702")){
  security_message(0);
}
