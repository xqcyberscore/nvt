###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_46597.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba 'FD_SET' Memory Corruption Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103095");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2011-03-01 13:10:12 +0100 (Tue, 01 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(46597);
  script_cve_id("CVE-2011-0719");
  script_name("Samba 'FD_SET' Memory Corruption Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46597");
  script_xref(name:"URL", value:"http://www.samba.org");
  script_xref(name:"URL", value:"http://samba.org/samba/security/CVE-2011-0719.html");

  tag_summary = "Samba is prone to a memory-corruption vulnerability.";

  tag_impact = "An attacker can exploit this issue to crash the application or cause
  the application to enter an infinite loop. Due to the nature of this
  issue, arbitrary code execution may be possible; this has not been confirmed.";

  tag_affected = "Samba versions prior to 3.5.7 are vulnerable.";

  tag_solution = "Updates are available. Please see the references for more information.";

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

if( version_is_less( version:vers, test_version:"3.5.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.7");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
