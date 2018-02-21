###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_samba_sec_bypass_vuln.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Security Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900685");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2009-1888");
  script_bugtraq_id(35472);
  script_name("Samba Format String Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35539");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1664");

  tag_solution = "Upgrade to 3.3.6 of Samba,
  http://us3.samba.org/samba/";

  tag_impact = "When dos filemode is set to yes in the smb.conf, attackers can exploit this
  issue to bypass certain security restrictions and compromise a user's system.

  Impact Level: System";

  tag_affected = "Samba 3.0.0 before 3.0.35 on Linux.
  Samba 3.1.x on Linux.
  Samba 3.2.4 before 3.2.13 on Linux.
  Samba 3.3.0 before 3.3.6 on Linux.";

  tag_insight = "The flaw is due to uninitialised memory access error in 'smbd' when denying
  attempts to modify a restricted access control list. This can be exploited
  to modify the ACL of an already writable file without required permissions.";

  tag_summary = "The host has Samba installed and is prone to Security Bypass
  Vulnerability.";

  script_tag(name:"affected", value:tag_affected);
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

if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.34" ) ||
    version_in_range( version:vers, test_version:"3.2", test_version2:"3.2.12" ) ||
    version_in_range( version:vers, test_version:"3.3", test_version2:"3.3.5" ) ||
    vers =~ "3.1" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.35/3.2.13/3.3.6");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
