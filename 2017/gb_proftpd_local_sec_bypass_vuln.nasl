###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proftpd_local_sec_bypass_vuln.nasl 5962 2017-04-18 08:01:50Z teissa $
#
# ProFTPD 'AllowChrootSymlinks' Local Security Bypass Vulnerability 
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810731");
  script_version("$Revision: 5962 $");
  script_cve_id("CVE-2017-7418");
  script_bugtraq_id(97409);
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 10:01:50 +0200 (Tue, 18 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-06 14:55:50 +0530 (Thu, 06 Apr 2017)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ProFTPD 'AllowChrootSymlinks' Local Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running ProFTPD server and
  is prone to local security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The ProFTPD controls whether the home
  directory of a user could contain a symbolic link through the
  AllowChrootSymlinks configuration option, but checks only the last path
  component when enforcing AllowChrootSymlinks.");

  script_tag(name:"impact", value:"Successful exploitation will allows
  attackers to bypass certain security restrictions and perform
  unauthorized actions. 

  Impact Level: Application");

  script_tag(name:"affected", value:"ProFTPD versions prior to 1.3.5e and
  1.3.6 prior to 1.3.6rc5 are vulnerable.");

  script_tag(name:"solution", value:"Upgrade ProFTPD 1.3.5e, 1.3.6rc5 or later,
  For updates refer to http://www.proftpd.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=4295");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/commit/ecff21e0d0e84f35c299ef91d7fda088e516d4ed");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/commit/f59593e6ff730b832dbe8754916cb5c821db579f");
  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/pull/444/commits/349addc3be4fcdad9bd4ec01ad1ccd916c898ed8");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for ProFTPD versions prior to 1.3.5e and 1.3.6 prior to 1.3.6rc5
if( version_is_less( version:vers, test_version:"1.3.5e" ) ||
    version_in_range(version:vers, test_version:"1.3.6", test_version2:"1.3.6.rc4")) 
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.5e/1.3.6rc5" );
  security_message( port:port, data:report );
  exit(0);
}
