###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_overflow_bug_win.nasl 9829 2018-05-15 07:08:59Z cfischer $
#
# OpenSSL Overflow Vulnerability - DEC 2017 (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107270");
  script_version("$Revision: 9829 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-15 09:08:59 +0200 (Tue, 15 May 2018) $");
  script_tag(name:"creation_date", value:"2017-12-08 12:22:37 +0100 (Fri, 08 Dec 2017)");
  script_cve_id("CVE-2017-3738");
  script_bugtraq_id(102118);

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Overflow Vulnerability - DEC 2017 (Windows)");

  script_tag(name: "summary", value: "This host is running OpenSSL and is prone
  to an overflow bug.");
  script_tag(name: "vuldetect", value: "Get the installed version and check if it is vulnerable.");

  script_tag(name: "insight", value: "The flaw is due to an overflow bug in the AVX2 Montgomery
    multiplication procedure used in exponentiation with 1024-bit moduli.");

  script_tag(name: "impact" , value: "Successfully exploiting this issue would allow an attacker to derive information about the private key.");

  script_tag(name: "affected", value: "OpenSSL 1.0.2 before 1.0.2n. OpenSSL 1.1.0 before 1.1.0h.

  NOTE: This issue only affects 64-bit installations.");

  script_tag(name: "solution", value: "OpenSSL 1.0.2 users should upgrade to 1.0.2n. OpenSSL 1.1.0 should upgrade to 1.1.0h
    when it is available, a fix is also available in commit e502cc86d in the OpenSSL git repository.");

  script_xref(name: "URL" , value: "https://www.openssl.org/news/secadv/20171207.txt");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_openssl_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenSSL/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe: CPE, port: Port)){
  exit(0);
}

if (Ver =~ "^(1\.0\.2)")
{
  if(version_is_less(version: Ver, test_version: "1.0.2n"))
  {
    report =  report_fixed_ver(installed_version: Ver, fixed_version: "1.0.2n");
    security_message(data: report, port: Port);
    exit( 0 );
  }
}
else if (Ver =~ "^(1\.1\.0)")
{
  if(version_is_less(version: Ver, test_version: "1.1.0h"))
  {
    report =  report_fixed_ver(installed_version: Ver, fixed_version: "1.1.0h");
    security_message(data: report, port: Port);
    exit( 0 );
  }
}

exit ( 99 );

