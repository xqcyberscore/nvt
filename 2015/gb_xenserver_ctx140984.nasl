###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx140984.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Citrix XenServer Multiple Security Updates (CTX200892)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105258");
  script_cve_id("CVE-2014-8106", "CVE-2014-7815", "CVE-2014-3615");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11872 $");

  script_name("Citrix XenServer Multiple Security Updates (CTX200892)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX200892");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have
been identified in Citrix XenServer. These vulnerabilities could, if exploited,
allow a malicious administrator of an HVM guest to compromise the host.

These vulnerabilities affect all currently supported versions of Citrix
XenServer up to and including Citrix XenServer 6.5.

The following vulnerabilities have been addressed:

  - CVE-2014-8106 (High): Heap-based buffer overflow in the Cirrus VGA emulator

  - CVE-2014-7815 (Low): The set_pixel_format function in QEMU allows a denial of service (crash)

  - CVE-2014-3615 (Low): The VGA emulator in QEMU allows users to read memory");

  script_tag(name:"affected", value:"XenServer 6.5
XenServer 6.2.0
XenServer 6.1.0
XenServer 6.0.2
XenServer 6.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-17 14:24:28 +0200 (Fri, 17 Apr 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("citrix_version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") ) exit( 0 );

patches = make_array();

patches['6.5.0'] = make_list( 'XS65E007' );
patches['6.2.0'] = make_list( 'XS62ESP1021' );
patches['6.1.0'] = make_list( 'XS61E051' );
patches['6.0.2'] = make_list( 'XS602E042' );
patches['6.0.0'] = make_list( 'XS60E046' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );

