###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_arbitrary_file_access.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Remote Arbitrary File Access
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:samba:samba";

#  Ref: Karol Wiesek - iDEFENSE

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15394");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(11216, 11281);
  script_cve_id("CVE-2004-0815");
  script_name("Samba Remote Arbitrary File Access");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  tag_summary = "The remote Samba server, according to its version number, is vulnerable
  to a remote file access vulnerability.";

  tag_impact = "This vulnerability allows an attacker to access arbitrary files which exist
  outside of the shares's defined path.";

  tag_insight = "An attacker needs a valid account to exploit this flaw.";

  tag_solution = "Upgrade to Samba 2.2.11 or 3.0.7";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.2.0", test_version2:"2.2.10" ) ||
    version_in_range( version:vers, test_version:"3.0.0", test_version2:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.11/3.0.7");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
