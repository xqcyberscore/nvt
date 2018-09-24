###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_dos_vuln_lin_jun09.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Denial Of Service Vulnerability in OpenSSL June-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800809");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-06-12 17:18:17 +0200 (Fri, 12 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1386");
  script_bugtraq_id(35174);
  script_name("Denial Of Service Vulnerability in OpenSSL June-09 (Linux)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_mandatory_keys("OpenSSL/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause DTLS server crash.");
  script_tag(name:"affected", value:"OpenSSL version prior to 0.9.8i on Linux.");
  script_tag(name:"insight", value:"A NULL pointer dereference error in ssl/s3_pkt.c file which does not properly
  check the input packets value via a DTLS ChangeCipherSpec packet that occurs
  before ClientHello.");
  script_tag(name:"summary", value:"This host has OpenSSL installed and is prone to Denial of Service
  vulnerability.");
  script_tag(name:"solution", value:"Upgrade to OpenSSL version 0.9.8i or later
  http://www.openssl.org/source

  *****
  Note: Vulnerability is related to CVE-2009-1386
  *****

  *****
  This might be a False Positive
  Only version check is being done depending on the publicly available OpenSSL packages.
  Each vendor might have backported versions of the packages.
  *****");

  script_xref(name:"URL", value:"http://cvs.openssl.org/chngview?cn=17369");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/06/02/1");
  script_xref(name:"URL", value:"http://rt.openssl.org/Ticket/Display.html?id=1679&user=guest&pass=guest");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:openssl:openssl");
sslVer = ereg_replace(pattern:"-", replace:".", string:ver);
if (sslVer != NULL) {
   if (version_is_less(version:sslVer, test_version:"0.9.8i")) {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
   }

   if (version_in_range(version:sslVer, test_version:"0.9.8i",
                        test_version2:"1.0.0.beta1")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
   }
}
