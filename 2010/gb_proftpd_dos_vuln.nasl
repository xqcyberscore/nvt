###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proftpd_dos_vuln.nasl 4774 2016-12-15 12:52:36Z cfi $
#
# ProFTPD Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801640");
  script_version("$Revision: 4774 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-15 13:52:36 +0100 (Thu, 15 Dec 2016) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2008-7265");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("ProFTPD Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3131");

  tag_impact = "Successful exploitation will allow attackers to cause a denial of service.
  Impact Level: Application";

  tag_affected = "ProFTPD versions prior to 1.3.2rc3";

  tag_insight = "The flaw is due to an error in 'pr_data_xfer()' function which allows
  remote authenticated users to cause a denial of service (CPU consumption)
  via an ABOR command during a data transfer.";

  tag_solution = "Upgrade to ProFTPD version 1.3.2rc3 or later,
  For updates refer to http://www.proftpd.org/";

  tag_summary = "The host is running ProFTPD and is prone to denial of service
  vulnerability.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for ProFTPD versions prior to 1.3.2rc3
if( version_is_less( version:vers, test_version:"1.3.2.rc3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.2rc3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );