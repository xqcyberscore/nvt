###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_badlock_vuln.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Badlock Critical Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807646");
  script_version("$Revision: 8882 $");
  script_cve_id("CVE-2016-2118", "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111",
                "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115",
                "CVE-2016-0128");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2016-04-14 14:39:10 +0530 (Thu, 14 Apr 2016)");
  script_name("Samba Badlock Critical Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"http://badlock.org/");
  script_xref(name:"URL", value:"http://thehackernews.com/2016/03/windows-samba-vulnerability.html");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to badlock vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The multiple flaws are due to
  - The Multiple errors in DCE-RPC code.
  - A spoofing Vulnerability in NETLOGON.
  - The LDAP implementation did not enforce integrity protection for LDAP connections.
  - The SSL/TLS certificates are not validated in certain connections.
  - Not enforcing Server Message Block (SMB) signing for clients using the SMB1 protocol.
  - An integrity protection for IPC traffic is not enabled by default
  - The MS-SAMR and MS-LSAD protocol implementations mishandle DCERPC connections.
  - An error in the implementation of NTLMSSP authentication.
  - ");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  leads to Man-in-the-middle (MITM) attacks, to causes denial of service, to spoof
  and to obtain sensitive session information.

  Impact Level: Application");

  script_tag(name:"affected", value:"Samba versions 3.0.x through 4.4.1
  -----
  NOTE: Samba versions 4.2.11, 4.3.8 are not affected
  -----");

  script_tag(name:"solution", value:"Upgrade to samba version 4.2.11, or 4.3.8,
  or 4.4.2, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! sambaPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! sambaVer = get_app_version( cpe:CPE, port:sambaPort ) ) exit( 0 );

## Below versions are not vulnerable
if( sambaVer == '4.2.11' || sambaVer == '4.3.8' || sambaVer == '4.4.2' ) exit( 0 );

if( sambaVer =~ "^(3|4)" ) {

  if( version_is_less( version:sambaVer, test_version:"4.4.2" ) ) {
    report = report_fixed_ver( installed_version:sambaVer, fixed_version:"4.2.11 or 4.3.8 or 4.4.2, or later" );
    security_message( data:report, port:sambaPort );
    exit( 0 );
  }
}

exit( 99 );
