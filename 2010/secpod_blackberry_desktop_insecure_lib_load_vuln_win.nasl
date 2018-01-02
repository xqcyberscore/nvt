###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_blackberry_desktop_insecure_lib_load_vuln_win.nasl 8254 2017-12-28 07:29:05Z teissa $
#
# BlackBerry Desktop Software Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to cause a target application to
  execute arbitrary code on the target user's system.
  Impact Level: Application";
tag_affected = "BlackBerry Desktop Software version prior to 6.0.0.47";
tag_insight = "Desktop Manager passes an insufficiently qualified path to the Windows
  operating system when loading an external library.";
tag_solution = "Upgrade to the BlackBerry Desktop Software version 6.0.0.47 or later,
  For updates refer to http://uk.blackberry.com/services/desktop/desktop_pc.jsp";
tag_summary = "This host is installed with BlackBerry Desktop Software and is prone
  to Insecure Library Loading Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902312");
  script_version("$Revision: 8254 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 08:29:05 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-2600");
  script_bugtraq_id(43139);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("BlackBerry Desktop Software Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41346");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Sep/1024425.html");
  script_xref(name : "URL" , value : "http://www.blackberry.com/btsc/search.do?cmd=displayKC&docType=kc&externalId=KB24242");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_blackberry_desktop_software_detect_win.nasl");
  script_require_keys("BlackBerry/Desktop/Win/Ver");
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

bbdVer = get_kb_item("BlackBerry/Desktop/Win/Ver");
if(!bbdVer){
  exit(0);
}

# Check for BlackBerry Desktop Software version less than 6.0.0.47
if(version_is_less(version:bbdVer, test_version:"6.0.0.47")){
  security_message(0);
}
