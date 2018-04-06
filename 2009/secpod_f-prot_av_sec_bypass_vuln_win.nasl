###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_f-prot_av_sec_bypass_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# F-PROT AntiVirus Security Bypass Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

CPE = "cpe:/a:f-prot:f-prot_antivirus";

tag_impact = "Attackers can exploit this issue to bypass the malware detection and
  to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "F-PROT AV version 6.0.9.1 and prior on Windows.";
tag_insight = "The flaw is due to an error in the file parsing engine while
  processing specially crafted CAB files.";
tag_solution = "Upgrade to F-PROT AV version 6.0.9.3 or later
  For updates refer to http://www.f-prot.com/";
tag_summary = "The host is installed with F-PROT AntiVirus and is prone to
  Security Bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900554");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1783");
  script_bugtraq_id(34896);
  script_name("F-PROT AntiVirus Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_f-prot_av_detect_win.nasl");
  script_mandatory_keys("F-Prot/AV/Win/Installed");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50427");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/advisory-f-prot-frisk-cab-bypass.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"6.0.9.1" ) ){
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.9.3", install_path:path);
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );