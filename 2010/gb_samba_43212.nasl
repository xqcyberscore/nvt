###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_43212.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba SID Parsing Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.100803");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 16:23:15 +0200 (Wed, 15 Sep 2010)");
  script_bugtraq_id(43212);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3069");
  script_name("Samba SID Parsing Remote Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43212");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/history/samba-3.5.5.html");
  script_xref(name:"URL", value:"http://www.samba.org");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CVE-2010-2069.html");

  tag_summary = "Samba is prone to a remote stack-based buffer-overflow vulnerability
  because it fails to properly bounds-check user-supplied data before
  copying it to an insufficiently sized memory buffer.";

  tag_impact = "An attacker can exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will
  likely result in a denial of service.";

  tag_affected = "Samba versions prior to 3.5.5 are vulnerable.";

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

if( version_is_less( version:vers, test_version:"3.5.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.5");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
