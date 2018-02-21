###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_38606.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba 'CAP_DAC_OVERRIDE' File Permissions Security Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100522");
  script_version("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-03-09 22:32:06 +0100 (Tue, 09 Mar 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_bugtraq_id(38606);
  script_cve_id("CVE-2010-0728");
  script_name("Samba 'CAP_DAC_OVERRIDE' File Permissions Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38606");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=7222");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CVE-2010-0728.html");

  tag_summary = "Samba is prone to a vulnerability that may allow attackers to bypass
  certain security restrictions.";

  tag_impact = "Successful exploits may allow attackers to gain unauthorized write and
  read access to files.";

  tag_affected = "This issue affects Samba versions 3.3.11, 3.4.6 and 3.5.0. Versions
  3.4.5 and prior and 3.3.10 and prior are not affected.";

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

if( version_is_equal( version:vers, test_version:"3.3.11" ) ||
    version_is_equal( version:vers, test_version:"3.4.6" ) ||
    version_is_equal( version:vers, test_version:"3.5.0" ) ||
    version_in_range( version:vers, test_version:"3.4", test_version2:"3.4.5" ) ||
    version_in_range( version:vers, test_version:"3.3", test_version2:"3.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references.");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
