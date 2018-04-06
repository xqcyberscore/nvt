###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_virtualbox_dos_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Sun VirtualBox or xVM VirtualBox Denial Of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will let attacker to exhaust the kernel memory of the
  guest operating system, leading to a Denial of Service against the guest
  operating system running in a virtual machine.
  Impact Level: Application.";
tag_affected = "Sun VirtualBox version 3.x before 3.0.10
  Sun xVM VirtualBox 1.6.x and 2.0.x before 2.0.12, 2.1.x, and 2.2.x";
tag_insight = "The flaw is due to the unspecified vulnerability in Guest Additions,
  via unknown vectors.";
tag_solution = "Upgrade to Sun VirtualBox version 3.0.10 or Sun xVM VirtualBox 2.0.12
  http://www.virtualbox.org/wiki/Downloads";
tag_summary = "This host is installed with Sun VirtualBox or xVM VirtualBox and is
  prone to Denial Of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901055");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3940");
  script_bugtraq_id(37024);
  script_name("Sun VirtualBox or xVM VirtualBox Denial Of Service Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37363/");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/387766.php");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-271149-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_require_keys("Sun/VirtualBox/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Check for product Sun VirtuaBox or Sun xVM VirtuaBox
vmVer = get_kb_item("Sun/VirtualBox/Lin/Ver");
if(!vmVer){
  exit(0);
}

vmVer = eregmatch(pattern:"([0-9]\.[0-9]+\.[0-9]+)", string:vmVer);
if(!vmVer[1]){
  exit(0);
}

if(version_in_range(version:vmVer[1], test_version:"1.6.0", test_version2:"1.6.6")||
   version_in_range(version:vmVer[1], test_version:"2.0.0", test_version2:"2.0.11")||
   version_in_range(version:vmVer[1], test_version:"2.1.0", test_version2:"2.1.4")||
   version_in_range(version:vmVer[1], test_version:"2.2.0", test_version2:"2.2.4")||
   version_in_range(version:vmVer[1], test_version:"3.0.0", test_version2:"3.0.9")){
  security_message(0);
}
