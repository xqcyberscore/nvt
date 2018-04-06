###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_files_del_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Novell File Reporter 'SRS' Tag Arbitrary File Deletion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:novell:file_reporter";

tag_impact = "Successful exploitation could allow remote attackers to delete
arbitrary files.

Impact Level: Application";

tag_affected = "Novell File Reporter (NFR) before 1.0.4.2";

tag_insight = "The flaw is due to an error in the NFR Agent (NFRAgent.exe)
when handling 'OPERATION'  and 'CMD' commands in the 'SRS' tag and can be
exploited to delete arbitrary files via a specially crafted SRS request
sent to TCP port 3073.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Novell File Reporter and is prone to
arbitrary file deletion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801960");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2750");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Novell File Reporter 'SRS' Tag Arbitrary File Deletion Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45071");
  script_xref(name : "URL" , value : "http://aluigi.org/adv/nfr_2-adv.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/518632/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/FileReporter/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for  Novell File Reporter version less than or equal 1.0.4.2
if( version_is_less_equal( version:vers, test_version:"1.0.400.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );