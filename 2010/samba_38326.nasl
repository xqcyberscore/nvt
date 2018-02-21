###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_38326.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba 'client/mount.cifs.c' Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100499");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-02-22 14:49:01 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(38326);
  script_cve_id("CVE-2010-0547", "CVE-2011-2724");
  script_name("Samba 'client/mount.cifs.c' Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38326");
  script_xref(name:"URL", value:"http://git.samba.org/?p=samba.git;a=commit;h=a065c177dfc8f968775593ba00dffafeebb2e054");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/");

  tag_summary = "Samba is prone to a remote denial-of-service vulnerability.";

  tag_impact = "A remote attacker can exploit this issue to crash the affected
  application, denying service to legitimate users.";

  tag_affected = "Samba 3.5.10 and earlier are vulnerable.";

  tag_solution = "Upgrade to Samba version 3.5.11 or later.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.5.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.11 or later");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
