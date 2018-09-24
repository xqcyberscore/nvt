###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssl_ca_cert_bypass_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# OpenSSL CA Certificate Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900464");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0653");
  script_name("OpenSSL CA Certificate Security Bypass Vulnerability");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_mandatory_keys("OpenSSL/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker spoof the SSL cerficate and
  gain sensitive information of the remote user through inserting a malicious
  URL in the contenxt of the openssl certificate.");
  script_tag(name:"affected", value:"OpenSSL version 0.9.6 or prior.");
  script_tag(name:"insight", value:"OpenSSL fails to verify the Basic Constraints for an intermediate CA-signed
  certificate.");
  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.0.0 or later,
  For further updates refer, http://www.openssl.org/news");
  script_tag(name:"summary", value:"This host is running OpenSSL and is prone to Security Bypass
  Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include ("version_func.inc");

opensslVer = get_kb_item("OpenSSL/Linux/Ver");
if(opensslVer != NULL)
{
  if(version_is_less_equal(version:opensslVer, test_version:"0.9.6")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
