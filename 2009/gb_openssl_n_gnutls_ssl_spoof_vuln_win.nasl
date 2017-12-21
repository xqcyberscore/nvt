###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_n_gnutls_ssl_spoof_vuln_win.nasl 8193 2017-12-20 10:46:55Z cfischer $
#
# OpenSSL/GnuTLS SSL Server Spoofing Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker spoof the SSL cerficate and gain
  unauthorized access.";
tag_affected = "OpenSSL version 0.9.8 through 0.9.8k
  GnuTLS version before 2.6.4 and before 2.7.4 on Windows";
tag_insight = "The NSS library used in these applications support MD2 with X.509
  certificates, which allows certificate to be spoofed using MD2 hash collision
  design flaws.";
tag_solution = "Upgrade to OpenSSL 1.0.0 or later and GnuTLS 2.6.4 or 2.7.4 or later.
  http://www.openssl.org/
  http://www.gnu.org/software/gnutls/";
tag_summary = "This host is running OpenSSL/GnuTLS and is prone to SSL server
  spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800917");
  script_version("$Revision: 8193 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 11:46:55 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2409");
  script_name("OpenSSL/GnuTLS SSL Server Spoofing Vulnerability (Windows)");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2009-2409");

  script_tag(name:"solution_type", value: "VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect_win.nasl", "gb_gnutls_detect_win.nasl");
  script_mandatory_keys("GnuTLS_or_OpenSSL/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

opensslInfos = get_app_version_and_location( cpe:"cpe:/a:openssl:openssl" );
opensslVers  = opensslInfos['version'];
opensslPath  = opensslInfos['location'];

if( opensslVers ) {
  # Grep for OpenSSL version 0.9.8 <= 0.9.8k
  if( version_in_range( version:opensslVers, test_version:"0.9.8", test_version2:"0.9.8k" ) ) {
    report = report_fixed_ver( installed_version:opensslVers, fixed_version:"1.0.0", install_path:opensslPath );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

gbutlsInfos = get_app_version_and_location( cpe:"cpe:/a:gnu:gnutls", exit_no_version:TRUE );
gnutlsVers  = gnutlsInfos['version'];
gnutlsPath  = gnutlsInfos['location'];

# Grep for GnuTLS version 2.6.0 < 2.6.4 and 2.7.0 < 2.7.4
if( version_in_range( version:gnutlsVers, test_version:"2.6.0", test_version2:"2.6.3" ) ||
    version_in_range( version:gnutlsVers, test_version:"2.7.0", test_version2:"2.7.3" ) ) {
  report = report_fixed_ver( installed_version:gnutlsVers, fixed_version:"2.6.4/2.7.4", install_path:gnutlsPath );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );