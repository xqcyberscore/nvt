###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_root_file_sys_sec_vuln.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Root File System Access Security Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800404");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0022");
  script_bugtraq_id(33118);
  script_name("Samba Root File System Access Security Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33379");
  script_xref(name:"URL", value:"http://liudieyu0.blog124.fc2.com/blog-entry-6.html");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CVE-2009-0022.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded");

  tag_impact = "Successful local exploitation could result in bypassing certain
  security restrictions by malicious users.

  Impact Level: System";

  tag_affected = "Samba 3.2.0 through 3.2.6 on Linux.";

  tag_insight = "Access to the root file system is granted when authenticated users connect
  to a share with an empty string as name.";

  tag_solution = "Upgrade to 3.2.7 of Samba,
  http://us3.samba.org/samba/";

  tag_summary = "The host has Samba installed and is prone to System Access Security
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

if( version_in_range( version:vers, test_version:"3.2.0", test_version2:"3.2.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.7");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
