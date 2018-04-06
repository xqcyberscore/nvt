###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_pls_file_bof_vuln_oct09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple iTunes '.pls' Files Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code within
  the context of the affected application, failed exploit attempts will result in
  a denial of service condition.
  Impact Level: Application";
tag_affected = "Apple iTunes version prior to 9.0.1 on Windows.";
tag_insight = "The flaw exists in the handling of specially crafted '.pls' files. It fails
  to bounds-check user-supplied data before copying it into an insufficiently
  sized buffer.";
tag_solution = "Upgrade to Apple iTunes Version 9.0.1
  http://www.apple.com/itunes/download";
tag_summary = "This host has Apple iTunes installed, which is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801105");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2817");
  script_bugtraq_id(36478);
  script_name("Apple iTunes '.pls' Files Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT3884");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2009/Sep/msg00006.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Check for iTunes version prior to 9.0.1 (9.0.1.8)
if( version_is_less( version:vers, test_version:"9.0.1.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.0.1.8", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );